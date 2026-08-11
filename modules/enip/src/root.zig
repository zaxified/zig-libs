// SPDX-License-Identifier: MIT

//! enip — pure-Zig **EtherNet/IP with CIP**: the protocol every Allen-Bradley
//! controller, and most of the industrial Ethernet devices around one, speaks
//! on TCP 44818 and UDP 2222/44818.
//!
//! Seven layers, each usable on its own:
//!
//! * **`encap`** (CIP Vol 2 ch. 2) — the 24-octet encapsulation header whose
//!   length field counts the data **after** it, the command set (`NOP`,
//!   `ListServices`, `ListIdentity`, `ListInterfaces`, `RegisterSession`,
//!   `UnRegisterSession`, `SendRRData`, `SendUnitData`), a stream `Framer`,
//!   and the identity/services payloads discovery answers with.
//! * **`cpf`** — the Common Packet Format item list every CIP message rides
//!   in, with the address-item-then-data-item ordering rules enforced rather
//!   than assumed, plus the connected data item's **sequence count** and the
//!   optional sockaddr items.
//! * **`epath`** (CIP Vol 1 App. C) — logical segments for class, instance,
//!   attribute, member and connection point in 8/16/32-bit forms with their
//!   **pad rules**, ANSI extended symbolic segments for tag names, port
//!   segments for routing, network segments and the electronic key.
//! * **`cip`** — the Message Router request and reply, the **reply bit
//!   `0x80`**, general and additional status, and `Multiple_Service_Packet`
//!   with its offset table.
//! * **`connmgr`** — the Connection Manager: `Unconnected_Send` with its route
//!   path and `2^tick × ticks` timeout, `Forward_Open`, `Large_Forward_Open`
//!   and `Forward_Close`.
//! * **`types`** — the CIP elementary types and the Logix tag services
//!   (`Read Tag`, `Write Tag`, and their fragmented forms), including
//!   structure handles and array element semantics.
//! * **`tagpath`** — the symbolic notation every Logix tool takes:
//!   `Program:MainProgram.MyUDT.Member`, `MyArray[3]`, `Matrix[1,2]`.
//!
//! On top of those, a `client` (register, read and write tags by name, batch
//! with a Multiple Service Packet, discover by `ListIdentity`, open and use a
//! Class 3 connection) and an `adapter` — the target side as a pure function
//! from one message to one message, which doubles as a fleet-simulation
//! target.
//!
//! Verified against **real traffic between two independent third-party client
//! stacks and a third-party target**, and by **live round trips in both
//! directions**; see `goldens.zig` and SPEC.md for exactly which frames came
//! from where and which are self-derived.
//!
//! Provenance: clean-room from the published ODVA CIP Volume 1 and Volume 2
//! frame layouts. No third-party source was consulted as a design reference;
//! third-party stacks were used as black boxes — to generate wire traffic and
//! to act as live peers — which is a test oracle, not a design reference. See
//! SPEC.md.

const std = @import("std");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

pub const meta = .{
    // The codecs, the client's logic and the adapter are pure computation;
    // only the optional TcpTransport/UdpDiscovery adapters touch std.Io.net.
    .platform = .any,
    .role = .both, // client + adapter
    // One Client/Adapter owns one connection's buffers, session handle and
    // sequence counters; nothing shared or global. Concurrency is the
    // caller's.
    .concurrency = .single_owner,
    .model_after = "ODVA CIP Volume 1 (Common Industrial Protocol) + Volume 2 (EtherNet/IP Adaptation); wire behaviour cross-checked against captured traffic between independent third-party stacks (see SPEC.md)",
    .deps = .{"netaddr"},
};

// ── layers ──────────────────────────────────────────────────────────────────

/// The 24-octet encapsulation header, its commands and a stream framer.
pub const encap = @import("encap.zig");
/// The Common Packet Format item list.
pub const cpf = @import("cpf.zig");
/// EPATH segments.
pub const epath = @import("epath.zig");
/// The CIP Message Router message.
pub const cip = @import("cip.zig");
/// The Connection Manager (class 0x06).
pub const connmgr = @import("connmgr.zig");
/// CIP data types and the Logix tag services.
pub const types = @import("types.zig");
/// The symbolic tag path notation.
pub const tagpath = @import("tagpath.zig");
/// The byte-stream seam and its adapters.
pub const transport = @import("transport.zig");
/// An EtherNet/IP client.
pub const client = @import("client.zig");
/// The target side (adapter / fleet-simulation target).
pub const adapter = @import("adapter.zig");
/// Byte-exact frames captured from third-party traffic.
pub const goldens = @import("goldens.zig");

// ── top-level names (the ones a consumer actually types) ────────────────────

/// An EtherNet/IP client over any byte stream.
pub const Client = client.Client;
pub const Config = client.Config;
pub const Routing = client.Routing;
pub const Connection = client.Connection;

/// The target side: answers out of caller-owned tag storage.
pub const Adapter = adapter.Adapter;
pub const AdapterConfig = adapter.Config;
pub const TagBinding = adapter.TagBinding;

/// The byte-stream seam: one `read`, one `write`.
pub const Transport = transport.Transport;
pub const TransportError = transport.TransportError;
/// Optional adapter onto a real socket.
pub const TcpTransport = transport.TcpTransport;
/// Optional adapter onto UDP, for `ListIdentity` discovery.
pub const UdpDiscovery = transport.UdpDiscovery;
/// In-memory pipe, for offline round trips.
pub const LoopTransport = transport.LoopTransport;
/// The registered explicit-messaging port (44818).
pub const default_port = encap.default_tcp_port;
/// The registered implicit (Class 0/1 I/O) UDP port (2222).
pub const io_udp_port = encap.io_udp_port;

pub const Command = encap.Command;
pub const Status = encap.Status;
pub const Identity = encap.Identity;
pub const Service = cip.Service;
pub const LogixService = cip.LogixService;
pub const ClassCode = cip.ClassCode;
pub const GeneralStatus = cip.GeneralStatus;
pub const DataType = types.DataType;
pub const Value = types.Value;
pub const TagData = types.TagData;
pub const parseTagPath = tagpath.parse;
pub const encodeTagPath = tagpath.encodePath;

/// Builds the `ListIdentity` datagram a discovery sweep broadcasts.
pub const encodeListIdentityRequest = client.encodeListIdentityRequest;
/// Decodes one device's answer to it.
pub const decodeListIdentityReply = client.decodeListIdentityReply;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ───────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s tests
// into the test binary on its own — every submodule must be named here too.
test {
    _ = encap;
    _ = cpf;
    _ = epath;
    _ = cip;
    _ = connmgr;
    _ = types;
    _ = tagpath;
    _ = transport;
    _ = client;
    _ = adapter;
    _ = goldens;
}

// ── tests: the whole stack, client against adapter ─────────────────────────

const testing = std.testing;

test "meta names exactly the one sibling dependency" {
    try testing.expectEqual(@as(usize, 1), meta.deps.len);
    try testing.expectEqualStrings("netaddr", meta.deps[0]);
}

/// A transport that hands every message the client writes straight to an
/// `Adapter` and queues its reply. That turns a full round trip into ordinary
/// synchronous code — no thread, no socket, no clock.
const PairedTransport = struct {
    target: *Adapter,
    out: [8192]u8 = undefined,
    queue: [16384]u8 = undefined,
    queue_len: usize = 0,
    queue_pos: usize = 0,
    /// Requests the adapter refused outright, so a test can assert on them.
    failures: usize = 0,

    fn seam(self: *PairedTransport) Transport {
        return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
    }

    fn readFn(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const self: *PairedTransport = @ptrCast(@alignCast(ctx));
        const avail = self.queue_len - self.queue_pos;
        if (avail == 0) return 0;
        const n = @min(avail, buf.len);
        @memcpy(buf[0..n], self.queue[self.queue_pos..][0..n]);
        self.queue_pos += n;
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *PairedTransport = @ptrCast(@alignCast(ctx));
        const reply = self.target.handle(bytes, &self.out) catch {
            self.failures += 1;
            return;
        };
        const r = reply orelse return;
        if (self.queue_len + r.len > self.queue.len) return error.WriteFailed;
        @memcpy(self.queue[self.queue_len..][0..r.len], r);
        self.queue_len += r.len;
    }
};

fn testTags(scada: []u8, dint: []u8, real: []u8) [3]TagBinding {
    return .{
        .{ .name = "SCADA", .type = .int, .bytes = scada },
        .{ .name = "TestTag", .type = .dint, .bytes = dint },
        .{ .name = "RealTag", .type = .real, .bytes = real },
    };
}

test "round trip: client against adapter over an in-memory wire" {
    var scada: [200]u8 = @splat(0);
    var dint: [40]u8 = @splat(0);
    var real: [20]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    // The adapter is a leaf device: it does not route, so the client must not
    // wrap in Unconnected_Send.
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });

    const handle = try c.registerSession();
    try testing.expect(handle != 0);
    try testing.expectEqual(handle, target.session_handle);

    // Identity, both ways of asking for it.
    const ident = try c.listIdentity();
    try testing.expectEqualStrings("zig-enip adapter", ident.product_name);
    try testing.expectEqual(@as(u32, 0x00C0FFEE), ident.serial_number);
    const svc = try c.listServices();
    try testing.expectEqualStrings("Communications", svc.trimmedName());
    try testing.expectEqual(@as(usize, 0), try c.listInterfaces());
    const name = try c.getAttributeSingle(@intFromEnum(ClassCode.identity), 1, 7);
    try testing.expectEqualStrings(
        "zig-enip adapter",
        (try types.decodeValue(.short_string, name)).string,
    );

    // Write a tag and read it back.
    var value: [2]u8 = undefined;
    std.mem.writeInt(i16, &value, -7, .little);
    try c.writeTag("SCADA[5]", .int, 1, &value);
    try testing.expectEqual(@as(i16, -7), std.mem.readInt(i16, scada[10..12], .little));
    const td = try c.readTag("SCADA[5]", 1);
    try testing.expectEqual(DataType.int, td.type);
    try testing.expectEqual(@as(i64, -7), (try td.at(0)).asInt().?);

    // An array read: four INTs from element 0.
    const four = try c.readTag("SCADA[0]", 4);
    try testing.expectEqual(@as(?usize, 4), four.elementCount());
    try testing.expectEqual(@as(i64, 0), (try four.at(0)).asInt().?);

    // A REAL, so the float path runs end to end.
    var f: [4]u8 = undefined;
    std.mem.writeInt(u32, &f, @bitCast(@as(f32, 3.5)), .little);
    try c.writeTag("RealTag[1]", .real, 1, &f);
    const rd = try c.readTag("RealTag[1]", 1);
    try testing.expectEqual(@as(f64, 3.5), (try rd.at(0)).asFloat().?);

    // A tag that does not exist comes back as a CIP error, not a crash.
    try testing.expectError(error.CipError, c.readTag("NoSuchTag", 1));
    // …and a write of the wrong type is refused rather than reinterpreted.
    try testing.expectError(error.CipError, c.writeTag("SCADA[0]", .dint, 1, &f));

    try c.unregisterSession();
    try testing.expectEqual(@as(u32, 0), target.session_handle);
    try testing.expectEqual(@as(usize, 0), paired.failures);
}

test "round trip: a multiple service packet batches three tags in one exchange" {
    var scada: [200]u8 = @splat(0);
    var dint: [40]u8 = @splat(0);
    var real: [20]u8 = @splat(0);
    std.mem.writeInt(i16, scada[0..2], 11, .little);
    std.mem.writeInt(i32, dint[0..4], 22, .little);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();

    const names = [_][]const u8{ "SCADA[0]", "TestTag[0]", "NoSuchTag" };
    var results: [3]?TagData = undefined;
    try testing.expectEqual(@as(usize, 3), try c.readTags(&names, &results));
    try testing.expectEqual(@as(i64, 11), (try results[0].?.at(0)).asInt().?);
    try testing.expectEqual(@as(i64, 22), (try results[1].?.at(0)).asInt().?);
    // The outer service succeeded; only the third embedded reply failed.
    try testing.expectEqual(@as(?TagData, null), results[2]);
    try testing.expectEqual(@as(usize, 0), paired.failures);
}

test "a multiple service packet larger than the reply table is refused, not truncated" {
    var scada: [200]u8 = @splat(0);
    var dint: [40]u8 = @splat(0);
    var real: [20]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);

    // One more embedded request than the adapter's fixed reply table
    // (`Adapter.max_batch`) holds. Each is a harmless, side-effect-free
    // `Get_Attributes_All` on Identity so the only thing under test is
    // whether the batch itself is accepted or refused.
    const over_cap = adapter.Adapter.max_batch + 1;
    var storage: [over_cap][32]u8 = undefined;
    var reqs: [over_cap][]const u8 = undefined;
    for (0..over_cap) |i| {
        reqs[i] = cip.getAttributesAll(@intFromEnum(cip.ClassCode.identity), 1, &storage[i]) catch unreachable;
    }
    var payload_buf: [1024]u8 = undefined;
    const payload = cip.MultipleService.encode(&reqs, &payload_buf) catch unreachable;

    var path_buf: [16]u8 = undefined;
    const router_path = epath.logicalPath(
        @intFromEnum(cip.ClassCode.message_router),
        1,
        null,
        &path_buf,
    ) catch unreachable;
    var wire_buf: [2048]u8 = undefined;
    const wire = (cip.Request{
        .service = @intFromEnum(cip.Service.multiple_service_packet),
        .path = router_path,
        .data = payload,
    }).encode(&wire_buf) catch unreachable;

    var out: [4096]u8 = undefined;
    const reply_bytes = try target.messageRouter(wire, &out);
    const reply = try cip.Reply.decode(reply_bytes);

    // A batch that cannot be fulfilled in full must come back as a CIP
    // error. The old behaviour silently capped the batch and replied
    // `success` with only `max_batch` embedded replies — indistinguishable
    // on the wire from every request having been honored, which drops the
    // request past the cap (e.g. a write) with no signal to the caller.
    try testing.expectEqual(cip.GeneralStatus.too_much_data, reply.general_status);
}

test "round trip: a routed client and an adapter that unwraps the route" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    // The default routing: every request wrapped in Unconnected_Send.
    var c = try Client.init(paired.seam(), &buf, .{});
    _ = try c.registerSession();

    var value: [2]u8 = undefined;
    std.mem.writeInt(i16, &value, 1234, .little);
    try c.writeTag("SCADA[2]", .int, 1, &value);
    const td = try c.readTag("SCADA[2]", 1);
    try testing.expectEqual(@as(i64, 1234), (try td.at(0)).asInt().?);
    try testing.expectEqual(@as(usize, 1), target.writes);
    try testing.expectEqual(@as(usize, 1), target.reads);
}

test "round trip: a Class 3 connection carries messages with sequence counts" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    std.mem.writeInt(i16, scada[0..2], 99, .little);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();

    const conn = try c.forwardOpen(.{ .size = 500 });
    try testing.expect(conn.o_to_t_id != 0);
    try testing.expect(target.connections[0].in_use);

    var req_buf: [64]u8 = undefined;
    const read = try client.encodeReadTag("SCADA[0]", 1, &req_buf);
    for (0..3) |_| {
        const reply = try c.sendConnectedCip(read);
        try testing.expect(reply.general_status.isSuccess());
        const td = try types.TagData.decode(reply.data);
        try testing.expectEqual(@as(i64, 99), (try td.at(0)).asInt().?);
    }
    // Three exchanges, three distinct sequence counts.
    try testing.expectEqual(@as(u16, 3), c.connection.?.sequence);

    try c.forwardClose();
    try testing.expect(!target.connections[0].in_use);
    try testing.expectError(error.NoConnection, c.sendConnectedCip(read));
}

test "Forward_Close only closes the connection whose full originator triple matches" {
    // adapter.zig's Forward_Close handler matches on {serial, vendor,
    // originator_serial} because the message carries no connection id. Only
    // the round-trip tests exercise a *matching* close; nothing before this
    // sent a Forward_Close with a wrong originator_serial and checked that
    // the still-open connection survives it.
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();

    const conn = try c.forwardOpen(.{ .size = 500 });
    try testing.expect(conn.o_to_t_id != 0);
    try testing.expect(target.connections[0].in_use);

    // Same connection_serial and vendor id as the open connection, but a
    // different originator_serial: this must NOT close it.
    var path_buf: [8]u8 = undefined;
    var b = epath.Builder.init(&path_buf);
    b.class(@intFromEnum(cip.ClassCode.message_router)) catch unreachable;
    b.instance(1) catch unreachable;
    const mismatched = connmgr.ForwardClose{
        .connection_serial = c.connection.?.serial,
        .originator_vendor_id = c.cfg.originator_vendor_id,
        .originator_serial = c.cfg.originator_serial +% 1,
        .connection_path = b.bytes(),
    };
    var wire_buf: [128]u8 = undefined;
    const wire = try mismatched.wrap(&wire_buf);
    const reply = try c.sendCip(wire);
    try testing.expect(!reply.general_status.isSuccess());
    try testing.expectEqual(cip.GeneralStatus.connection_failure, reply.general_status);
    try testing.expectEqual(
        @as(u16, @intFromEnum(connmgr.ExtendedStatus.connection_not_found)),
        reply.extendedStatus().?,
    );
    try testing.expect(target.connections[0].in_use); // still open

    // The real Forward_Close (matching triple) does close it.
    try c.forwardClose();
    try testing.expect(!target.connections[0].in_use);
}

test "Forward_Open past the connection pool's capacity is refused, not stolen from another originator" {
    // The adapter has a fixed-size connection pool (`connections: [4]`).
    // Nothing before this ever opened more than one connection at a time
    // against a single adapter, so the pool-exhaustion path in
    // `freeConnection`/Forward_Open's slot search had no test at all.
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);

    var path_buf: [8]u8 = undefined;
    var b = epath.Builder.init(&path_buf);
    b.class(@intFromEnum(cip.ClassCode.message_router)) catch unreachable;
    b.instance(1) catch unreachable;

    const params = connmgr.ConnectionParameters{ .size = 500, .variable = true };
    var out: [256]u8 = undefined;

    var opened: [4]u32 = undefined;
    for (0..4) |i| {
        var wire_buf: [256]u8 = undefined;
        const fo = connmgr.ForwardOpen{
            .o_to_t_connection_id = 0,
            .t_to_o_connection_id = 0,
            .connection_serial = @intCast(100 + i),
            .originator_vendor_id = 0x1234,
            .originator_serial = 1,
            .o_to_t_rpi = 10_000,
            .o_to_t_params = params,
            .t_to_o_rpi = 10_000,
            .t_to_o_params = params,
            .connection_path = b.bytes(),
        };
        const wire = try fo.wrap(&wire_buf);
        const raw = try target.messageRouter(wire, &out);
        const reply = try cip.Reply.decode(raw);
        try testing.expect(reply.general_status.isSuccess());
        const fr = try connmgr.ForwardOpenReply.decode(reply.data);
        opened[i] = fr.o_to_t_connection_id;
    }
    for (&target.connections) |c| try testing.expect(c.in_use);

    // A 5th Forward_Open finds no free slot.
    var wire_buf5: [256]u8 = undefined;
    const fo5 = connmgr.ForwardOpen{
        .o_to_t_connection_id = 0,
        .t_to_o_connection_id = 0,
        .connection_serial = 200,
        .originator_vendor_id = 0x1234,
        .originator_serial = 1,
        .o_to_t_rpi = 10_000,
        .o_to_t_params = params,
        .t_to_o_rpi = 10_000,
        .t_to_o_params = params,
        .connection_path = b.bytes(),
    };
    const wire5 = try fo5.wrap(&wire_buf5);
    const raw5 = try target.messageRouter(wire5, &out);
    const reply5 = try cip.Reply.decode(raw5);
    try testing.expect(!reply5.general_status.isSuccess());
    try testing.expectEqual(cip.GeneralStatus.connection_failure, reply5.general_status);
    try testing.expectEqual(
        @as(u16, @intFromEnum(connmgr.ExtendedStatus.connection_limit_reached)),
        reply5.extendedStatus().?,
    );

    // None of the four already-open connections were disturbed.
    for (target.connections, 0..) |c, i| {
        try testing.expect(c.in_use);
        try testing.expectEqual(@as(u16, @intCast(100 + i)), c.serial);
        try testing.expectEqual(opened[i], c.o_to_t_id);
    }
}

test "round trip: a large connection uses the Large_Forward_Open form" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    const conn = try c.forwardOpen(.{ .size = 4000 });
    try testing.expectEqual(@as(u16, 4000), conn.size);
    try c.forwardClose();
}

test "round trip: a fragmented read reassembles a tag larger than one reply" {
    var scada: [400]u8 = undefined;
    for (&scada, 0..) |*b, i| b.* = @intCast(i % 251);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    // A tiny reply ceiling forces the partial-transfer path.
    var target = Adapter.init(.{ .max_reply = 64 }, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();

    var out: [400]u8 = undefined;
    const td = try c.readTagFragmented("SCADA[0]", 200, &out);
    try testing.expectEqual(DataType.int, td.type);
    try testing.expectEqualSlices(u8, &scada, td.data);
    // It really did take several exchanges.
    try testing.expect(target.reads > 5);
}

test "round trip: a fragmented write splits without splitting an element" {
    var scada: [400]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();

    var values: [400]u8 = undefined;
    for (&values, 0..) |*b, i| b.* = @intCast((i * 7) % 251);
    try c.writeTagFragmented("SCADA[0]", .int, 200, &values, 50);
    try testing.expectEqualSlices(u8, &values, &scada);
    try testing.expect(target.writes >= 8);
}

test "round trip: an adapter refuses Reset unless it was allowed" {
    var scada: [8]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    try testing.expectError(error.CipError, c.reset(@intFromEnum(ClassCode.identity), 1));
    try testing.expect(!target.reset_requested);

    var allowed = Adapter.init(.{ .allow_reset = true }, &tags);
    var paired2 = PairedTransport{ .target = &allowed };
    var buf2: [8192]u8 = undefined;
    var c2 = try Client.init(paired2.seam(), &buf2, .{ .routing = .direct });
    _ = try c2.registerSession();
    try c2.reset(@intFromEnum(ClassCode.identity), 1);
    try testing.expect(allowed.reset_requested);
}

// ── discovery: the Program Name and Symbol objects ─────────────────────────
//
// `goldens.zig`'s `discovery_table` anchors the happy path against a real
// stock `LogixDriver`'s own parsers. These cover what that one session does
// not reach: a scalar, a binding the list must leave out, the continuation
// across replies, and the refusals.

/// One `Get_Instance_Attribute_List` request for attributes 1 (name), 2
/// (symbol type) and 8 (array dimensions), resuming at `start_instance`.
/// Everything referenced is copied into `out` by `Request.encode`.
fn symbolListRequest(start_instance: u32, out: []u8) []const u8 {
    var path_buf: [16]u8 = undefined;
    const path = epath.logicalPath(
        @intFromEnum(cip.ClassCode.symbol),
        start_instance,
        null,
        &path_buf,
    ) catch unreachable;
    const attrs = [_]u16{ 1, 2, 8 };
    var data_buf: [2 + attrs.len * 2]u8 = undefined;
    std.mem.writeInt(u16, data_buf[0..2], attrs.len, .little);
    for (attrs, 0..) |a, i| std.mem.writeInt(u16, data_buf[2 + i * 2 ..][0..2], a, .little);
    return (cip.Request{
        .service = cip.LogixService.get_instance_attribute_list,
        .path = path,
        .data = &data_buf,
    }).encode(out) catch unreachable;
}

const SymbolRecord = struct {
    id: u32,
    name: []const u8,
    symbol_type: u16,
    dims: [3]u32,
};

/// Decodes the reply body `symbolListRequest` asks for. Deliberately written
/// against that exact attribute list rather than generically, so a record
/// laid out in some other order fails to parse instead of being tolerated.
fn parseSymbolRecords(data: []const u8, out: []SymbolRecord) !usize {
    var off: usize = 0;
    var n: usize = 0;
    while (off < data.len) : (n += 1) {
        if (n == out.len) return error.TooManyRecords;
        if (off + 6 > data.len) return error.Truncated;
        const id = std.mem.readInt(u32, data[off..][0..4], .little);
        off += 4;
        const len = std.mem.readInt(u16, data[off..][0..2], .little);
        off += 2;
        if (off + len + 2 + 12 > data.len) return error.Truncated;
        const name = data[off..][0..len];
        off += len;
        const st = std.mem.readInt(u16, data[off..][0..2], .little);
        off += 2;
        var dims: [3]u32 = undefined;
        for (&dims) |*d| {
            d.* = std.mem.readInt(u32, data[off..][0..4], .little);
            off += 4;
        }
        out[n] = .{ .id = id, .name = name, .symbol_type = st, .dims = dims };
    }
    return n;
}

test "the tag list calls a one-element binding a scalar and an array by its element count" {
    var speed: [4]u8 = @splat(0);
    var counts: [24]u8 = @splat(0);
    const tags = [_]TagBinding{
        .{ .name = "Speed", .type = .dint, .bytes = &speed },
        .{ .name = "Counts", .type = .dint, .bytes = &counts },
    };
    var target = Adapter.init(.{}, &tags);

    var req_buf: [64]u8 = undefined;
    var out: [1024]u8 = undefined;
    const reply = try cip.Reply.decode(
        try target.messageRouter(symbolListRequest(0, &req_buf), &out),
    );
    try testing.expectEqual(cip.GeneralStatus.success, reply.general_status);

    var recs: [4]SymbolRecord = undefined;
    try testing.expectEqual(@as(usize, 2), try parseSymbolRecords(reply.data, &recs));

    // The scalar: dimension bits clear, and dimensions all zero. A device
    // that advertised DINT[1] here would make a client hand back `[1500]`
    // where the program expects `1500`.
    try testing.expectEqualStrings("Speed", recs[0].name);
    try testing.expectEqual(@as(u32, 1), recs[0].id);
    try testing.expectEqual(@as(u16, 0x00C4), recs[0].symbol_type);
    try testing.expectEqual([3]u32{ 0, 0, 0 }, recs[0].dims);

    // The array: one dimension (bit 13), six elements — not six bytes, and
    // not the 24 octets the binding actually holds.
    try testing.expectEqualStrings("Counts", recs[1].name);
    try testing.expectEqual(@as(u32, 2), recs[1].id);
    try testing.expectEqual(@as(u16, 0x20C4), recs[1].symbol_type);
    try testing.expectEqual([3]u32{ 6, 0, 0 }, recs[1].dims);
}

test "a binding whose element width is unknown is left out of the tag list but stays readable" {
    var scalar: [4]u8 = @splat(0);
    var opaque_bytes: [8]u8 = @splat(0);
    std.mem.writeInt(i32, scalar[0..4], 5, .little);
    const tags = [_]TagBinding{
        // A structure needs a Template Object (class 0x6C) to be described,
        // and this adapter has none — so it must not appear in a tag list
        // that would promise one.
        .{ .name = "Recipe", .type = .structure, .bytes = &opaque_bytes },
        .{ .name = "Speed", .type = .dint, .bytes = &scalar },
    };
    var target = Adapter.init(.{}, &tags);
    try testing.expect(!tags[0].isEnumerable());
    try testing.expect(tags[1].isEnumerable());

    var req_buf: [64]u8 = undefined;
    var out: [1024]u8 = undefined;
    const reply = try cip.Reply.decode(
        try target.messageRouter(symbolListRequest(0, &req_buf), &out),
    );
    try testing.expectEqual(cip.GeneralStatus.success, reply.general_status);
    var recs: [4]SymbolRecord = undefined;
    const n = try parseSymbolRecords(reply.data, &recs);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("Speed", recs[0].name);
    // Its id is its position in the binding table, so the omitted neighbour
    // did not renumber it.
    try testing.expectEqual(@as(u32, 2), recs[0].id);

    // Invisible to discovery is not absent from the device: it still reads by
    // name, which is the whole claim `isEnumerable`'s doc comment makes.
    var read_buf: [64]u8 = undefined;
    const read = try client.encodeReadTag("Recipe", 1, &read_buf);
    const rr = try cip.Reply.decode(try target.messageRouter(read, &out));
    try testing.expectEqual(cip.GeneralStatus.success, rr.general_status);
}

test "the tag list resumes where the previous reply stopped instead of dropping the rest" {
    var storage: [6][4]u8 = @splat(@splat(0));
    var tags: [6]TagBinding = undefined;
    const names = [_][]const u8{ "TagA", "TagB", "TagC", "TagD", "TagE", "TagF" };
    for (&tags, names, &storage) |*t, name, *bytes| {
        t.* = .{ .name = name, .type = .dint, .bytes = bytes };
    }
    // Small enough that the six records cannot be answered in one reply.
    var target = Adapter.init(.{ .max_reply = 80 }, &tags);

    var req_buf: [64]u8 = undefined;
    var out: [1024]u8 = undefined;
    var seen: [6][]const u8 = undefined;
    var total: usize = 0;
    var next: u32 = 0;
    var rounds: usize = 0;
    var saw_partial = false;
    while (rounds < 10) : (rounds += 1) {
        const reply = try cip.Reply.decode(
            try target.messageRouter(symbolListRequest(next, &req_buf), &out),
        );
        var recs: [6]SymbolRecord = undefined;
        const n = try parseSymbolRecords(reply.data, &recs);
        // Progress is mandatory: a reply that says "more" while returning
        // nothing is the shape that spins a client forever.
        try testing.expect(n > 0);
        for (recs[0..n]) |r| {
            // The names are copied out because `reply.data` points into `out`,
            // which the next round overwrites.
            seen[total] = names[r.id - 1];
            try testing.expectEqualStrings(seen[total], r.name);
            total += 1;
            next = r.id + 1;
        }
        if (reply.general_status == .success) break;
        try testing.expectEqual(cip.GeneralStatus.partial_transfer, reply.general_status);
        saw_partial = true;
    }
    // The point of the test: it took more than one reply, and nothing was
    // lost between them.
    try testing.expect(saw_partial);
    try testing.expectEqual(@as(usize, 6), total);
    for (names, seen) |want, got| try testing.expectEqualStrings(want, got);
}

test "an attribute the Symbol Object does not implement is refused, and refused whole" {
    var speed: [4]u8 = @splat(0);
    const tags = [_]TagBinding{.{ .name = "Speed", .type = .dint, .bytes = &speed }};
    var target = Adapter.init(.{}, &tags);

    var path_buf: [16]u8 = undefined;
    const path = try epath.logicalPath(@intFromEnum(cip.ClassCode.symbol), 0, null, &path_buf);
    // Attribute 1 is supported, 4 is not. The supported one being first is
    // the point: the refusal must not arrive after a partial record.
    const attrs = [_]u16{ 1, 4 };
    var data_buf: [2 + attrs.len * 2]u8 = undefined;
    std.mem.writeInt(u16, data_buf[0..2], attrs.len, .little);
    for (attrs, 0..) |a, i| std.mem.writeInt(u16, data_buf[2 + i * 2 ..][0..2], a, .little);
    var req_buf: [64]u8 = undefined;
    const req = try (cip.Request{
        .service = cip.LogixService.get_instance_attribute_list,
        .path = path,
        .data = &data_buf,
    }).encode(&req_buf);

    var out: [1024]u8 = undefined;
    const reply = try cip.Reply.decode(try target.messageRouter(req, &out));
    try testing.expectEqual(cip.GeneralStatus.attribute_not_supported, reply.general_status);
    try testing.expectEqual(@as(usize, 0), reply.data.len);
}

test "the Symbol Object's service code means nothing on another class" {
    var speed: [4]u8 = @splat(0);
    const tags = [_]TagBinding{.{ .name = "Speed", .type = .dint, .bytes = &speed }};
    var target = Adapter.init(.{}, &tags);

    var path_buf: [16]u8 = undefined;
    // Same service code, Identity class instead of the Symbol Object.
    const path = try epath.logicalPath(@intFromEnum(cip.ClassCode.identity), 0, null, &path_buf);
    var req_buf: [64]u8 = undefined;
    const req = try (cip.Request{
        .service = cip.LogixService.get_instance_attribute_list,
        .path = path,
        .data = &[_]u8{ 1, 0, 1, 0 },
    }).encode(&req_buf);

    var out: [1024]u8 = undefined;
    const reply = try cip.Reply.decode(try target.messageRouter(req, &out));
    try testing.expectEqual(cip.GeneralStatus.service_not_supported, reply.general_status);
}

test "the Program Name object answers instance 1 only, and can be withheld entirely" {
    var speed: [4]u8 = @splat(0);
    const tags = [_]TagBinding{.{ .name = "Speed", .type = .dint, .bytes = &speed }};
    var out: [1024]u8 = undefined;
    var req_buf: [64]u8 = undefined;
    const class = @intFromEnum(cip.ClassCode.program_name);

    var target = Adapter.init(.{ .program_name = "MainProgram" }, &tags);
    const ok = try cip.Reply.decode(try target.messageRouter(
        try cip.getAttributesAll(class, 1, &req_buf),
        &out,
    ));
    try testing.expectEqual(cip.GeneralStatus.success, ok.general_status);
    // A `STRING`: 16-bit length, then the octets, no terminator and no pad.
    try testing.expectEqual(@as(usize, 2 + 11), ok.data.len);
    try testing.expectEqual(@as(u16, 11), std.mem.readInt(u16, ok.data[0..2], .little));
    try testing.expectEqualStrings("MainProgram", ok.data[2..]);

    // No second instance exists.
    const other = try cip.Reply.decode(try target.messageRouter(
        try cip.getAttributesAll(class, 2, &req_buf),
        &out,
    ));
    try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, other.general_status);

    // Withheld: the class answers exactly as it did before it existed, which
    // is what a device with no Program Name object genuinely says.
    var without = Adapter.init(.{ .program_name = "" }, &tags);
    const none = try cip.Reply.decode(try without.messageRouter(
        try cip.getAttributesAll(class, 1, &req_buf),
        &out,
    ));
    try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, none.general_status);

    // And serving it must not have been counted as an identity request.
    try testing.expectEqual(@as(usize, 0), target.identity_requests);
}

test "a symbol instance id addresses the same tag as its name, and an unknown one is refused" {
    var speed: [4]u8 = @splat(0);
    var counts: [24]u8 = @splat(0);
    std.mem.writeInt(i32, counts[4..8], 77, .little);
    const tags = [_]TagBinding{
        .{ .name = "Speed", .type = .dint, .bytes = &speed },
        .{ .name = "Counts", .type = .dint, .bytes = &counts },
    };
    var target = Adapter.init(.{}, &tags);
    var out: [1024]u8 = undefined;

    // `20 6B 24 02 28 01` — the Symbol Object, instance 2, member 1: the same
    // element `Counts[1]` names.
    var path_buf: [16]u8 = undefined;
    var pb = epath.Builder.init(&path_buf);
    try pb.class(@intFromEnum(cip.ClassCode.symbol));
    try pb.instance(2);
    try pb.member(1);
    var req_buf: [64]u8 = undefined;
    const req = try (cip.Request{
        .service = cip.LogixService.read_tag,
        .path = pb.bytes(),
        .data = &[_]u8{ 1, 0 },
    }).encode(&req_buf);
    const reply = try cip.Reply.decode(try target.messageRouter(req, &out));
    try testing.expectEqual(cip.GeneralStatus.success, reply.general_status);
    const td = try types.TagData.decode(reply.data);
    try testing.expectEqual(DataType.dint, td.type);
    try testing.expectEqual(@as(i64, 77), (try td.at(0)).asInt().?);

    // An id past the end of the binding table names nothing.
    var missing_path: [16]u8 = undefined;
    var mb = epath.Builder.init(&missing_path);
    try mb.class(@intFromEnum(cip.ClassCode.symbol));
    try mb.instance(99);
    const missing = try (cip.Request{
        .service = cip.LogixService.read_tag,
        .path = mb.bytes(),
        .data = &[_]u8{ 1, 0 },
    }).encode(&req_buf);
    const refused = try cip.Reply.decode(try target.messageRouter(missing, &out));
    try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, refused.general_status);
}

test "round trip: a message before RegisterSession is refused at the encapsulation layer" {
    var scada: [8]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    // The client refuses on its own…
    try testing.expectError(error.NoSession, c.readTag("SCADA[0]", 1));
    // …and so does the adapter when the check is bypassed.
    var req: [64]u8 = undefined;
    const inner = try client.encodeReadTag("SCADA[0]", 1, &req);
    const items = cpf.unconnectedItems(inner);
    var env_buf: [128]u8 = undefined;
    const env = try cpf.encodeEnvelope(0, 0, &items, &env_buf);
    var frame_buf: [256]u8 = undefined;
    const framed = try encap.encode(.{
        .command = .send_rr_data,
        .session_handle = 0,
        .status = .success,
        .sender_context = @splat(0),
        .options = 0,
        .data = env,
        .total_len = 0,
    }, &frame_buf);
    var out: [256]u8 = undefined;
    const reply = (try target.handle(framed, &out)).?;
    const msg = try encap.decode(reply);
    try testing.expectEqual(Status.invalid_session_handle, msg.status);
    try testing.expectEqual(@as(usize, 0), msg.data.len);
}

test "the adapter never panics on hostile encapsulation input" {
    var scada: [16]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var out: [1024]u8 = undefined;

    const hostile = [_][]const u8{
        // Truncated header.
        &[_]u8{ 0x6F, 0x00 },
        // Length disagreeing with the payload.
        &([_]u8{ 0x6F, 0x00, 0xFF, 0x00 } ++ [_]u8{0} ** 20),
        // SendRRData with an empty body.
        &([_]u8{ 0x6F, 0x00, 0x00, 0x00 } ++ [_]u8{0} ** 20),
        // A CPF item count that overruns.
        &([_]u8{ 0x6F, 0x00, 0x08, 0x00 } ++ [_]u8{0} ** 20 ++
            [_]u8{ 0, 0, 0, 0, 0, 0, 0xFF, 0xFF }),
        // An unknown command.
        &([_]u8{ 0x34, 0x12, 0x00, 0x00 } ++ [_]u8{0} ** 20),
    };
    for (hostile) |h| {
        _ = target.handle(h, &out) catch continue;
    }
}

test "fuzz: the adapter never panics on arbitrary messages" {
    try std.testing.fuzz({}, fuzzAdapter, .{});
}

// F6 (2026-08-11 re-audit): `Config.max_reply`'s default (4000) used to be
// structurally unreachable from `fuzzAdapter` — `out` was `[2048]u8`, smaller
// than the default, so `@min(cfg.max_reply, out.len)` had `out.len` as the
// binding term on every single run, no matter what bytes were generated. Both
// sizes below exist so that is no longer categorically true: `fuzz_out_len`
// is bigger than the shipped default so `max_reply` *can* be the binding
// term, and `fuzz_scada_len` is bigger than the body room that leaves
// (`max_reply - 8`) so a full read of it *can* exceed that room. See the
// deterministic test below, which proves (rather than hopes) the cap fires
// under this exact shape — a random byte fuzzer essentially never lands a
// specific service + path + oversized count by chance (the same "weighted
// branch" reachability gap the campaign has documented elsewhere).
const fuzz_scada_len = 4200;
const fuzz_out_len = 8192;

fn fuzzAdapter(_: void, smith: *std.testing.Smith) !void {
    var scada: [fuzz_scada_len]u8 = @splat(0);
    var dint: [16]u8 = @splat(0);
    var real: [16]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    // Half the runs start with a session already open, so the paths past the
    // session check are reachable.
    if (smith.boolWeighted(1, 1)) target.session_handle = 0xA5A5_0001;

    var input: [1024]u8 = undefined;
    smith.bytes(&input);
    const len: usize = smith.valueRangeAtMost(u16, 0, input.len);
    var out: [fuzz_out_len]u8 = undefined;
    const reply = target.handle(input[0..len], &out) catch return;
    const r = reply orelse return;
    // Anything the adapter emits must itself be a legal message.
    const msg = try encap.decode(r);
    try testing.expectEqual(r.len, msg.total_len);
}

/// Builds the CIP `Read Tag Fragmented` request bytes `Client.readTagFragmented`
/// would send for round 0 (offset 0), without needing a live `Client`/transport
/// round trip — the same low-level building blocks `messageRouter` itself
/// consumes.
fn readTagFragmentedRequest(name: []const u8, count: u16, out: []u8) ![]const u8 {
    var path_buf: [256]u8 = undefined;
    const path = try tagpath.encodePath(name, &path_buf);
    var data_buf: [6]u8 = undefined;
    const data = try (types.ReadTagFragmentedRequest{ .count = count, .byte_offset = 0 }).encode(&data_buf);
    return (cip.Request{
        .service = cip.LogixService.read_tag_fragmented,
        .path = path,
        .data = data,
    }).encode(out);
}

test "F6: the SHIPPED default max_reply (Config omits it) actually binds under the exact shape fuzzAdapter now uses" {
    // Half 1 of F6: pins the literal 4000 (as `4000 - 8 = 3992`, the body
    // room `readTag`'s `-| 8` encapsulation-header accounting leaves) rather
    // than `cfg.max_reply` or `cfg.max_reply - 8`, so a change to the
    // constant moves this number out from under the test.
    //
    // Half 2 of F6: proves — by direct construction, not by sampling — that
    // the cap is reachable under `fuzz_scada_len`/`fuzz_out_len`, the exact
    // shape `fuzzAdapter` now uses. `readTagFragmentedRequest` builds the same
    // bytes `Client.readTagFragmented`'s round 0 would put on the wire.
    var scada: [fuzz_scada_len]u8 = undefined;
    for (&scada, 0..) |*b, i| b.* = @intCast(i % 251);
    var dint: [16]u8 = @splat(0);
    var real: [16]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags); // max_reply NOT set: the shipped default.

    // SCADA is `.int` (2-byte elements); ask for more than fits in one reply.
    var req_buf: [512]u8 = undefined;
    const req = try readTagFragmentedRequest("SCADA[0]", fuzz_scada_len / 2, &req_buf);

    var out: [fuzz_out_len]u8 = undefined; // > 4000, so max_reply is the binding term.
    const reply = try cip.Reply.decode(try target.messageRouter(req, &out));
    try testing.expectEqual(cip.GeneralStatus.partial_transfer, reply.general_status);
    const td = try types.TagData.decode(reply.data);
    // The literal: 4000 (max_reply) - 8 (encap header accounting) = 3992 is
    // the most data any single reply can carry by default — not "however
    // much max_reply happens to allow".
    try testing.expectEqual(@as(usize, 3992), td.data.len);
    try testing.expectEqualSlices(u8, scada[0..3992], td.data);
}

test "fuzz: a client survives an arbitrary reply without panicking" {
    try std.testing.fuzz({}, fuzzClientReply, .{});
}

fn fuzzClientReply(_: void, smith: *std.testing.Smith) !void {
    var lt: transport.LoopTransport = .{};
    var reply: [512]u8 = undefined;
    smith.bytes(&reply);
    const len: usize = smith.valueRangeAtMost(u16, 24, reply.len);
    // Make it a plausible frame so the decoder gets past the header.
    reply[0] = 0x6F;
    reply[1] = 0x00;
    std.mem.writeInt(u16, reply[2..4], @intCast(len - 24), .little);
    @memset(reply[20..24], 0);
    lt.deliver(reply[0..len]);

    var buf: [4096]u8 = undefined;
    var c = try Client.init(lt.transport(), &buf, .{ .routing = .direct });
    c.registered = true;
    c.session_handle = std.mem.readInt(u32, reply[4..8], .little);
    _ = c.readTag("SCADA", 1) catch {};
}

// ── live interop ────────────────────────────────────────────────────────────
//
// All three tests print `SKIPPED: …` and pass when no peer is present, exactly
// like the live tests in `s7comm`, `iec104` and `bacnet`.

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

const Endpoint = struct { host: []const u8, port: u16 };

fn splitEndpoint(endpoint: []const u8) ?Endpoint {
    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return null;
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return null;
    return .{ .host = endpoint[0..colon], .port = port };
}

fn directRouting() bool {
    const r = envVar("ENIP_TEST_ROUTE") orelse return false;
    return std.mem.eql(u8, r, "direct");
}

// Set ENIP_TEST_SERVER=host:port to run a real round trip against a live
// EtherNet/IP target. ENIP_TEST_TAG names an INT tag that may be written
// (default `SCADA`), ENIP_TEST_DINT_TAG a DINT one (default `TestTag`).
// ENIP_TEST_ROUTE=direct sends bare CIP messages, which is what a
// non-routing device wants.
test "live: our client against a real EtherNet/IP target" {
    const endpoint = envVar("ENIP_TEST_SERVER") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live EtherNet/IP interop (set ENIP_TEST_SERVER=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;
    const tag = envVar("ENIP_TEST_TAG") orelse "SCADA";
    const dint_tag = envVar("ENIP_TEST_DINT_TAG") orelse "TestTag";

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var tt = TcpTransport.connect(io, addr) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live EtherNet/IP interop (cannot connect to {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer tt.close();
    tt.setReadTimeout(3000);

    var buf: [16384]u8 = undefined;
    var c = try Client.init(tt.transport(), &buf, .{
        .routing = if (directRouting()) .direct else .{ .unconnected_send = &connmgr.backplane_slot_0 },
    });

    const session = try c.registerSession();
    try testing.expect(session != 0);

    // Identity and services, straight off the encapsulation layer.
    const ident = try c.listIdentity();
    var product: [64]u8 = undefined;
    const product_len = @min(product.len, ident.product_name.len);
    @memcpy(product[0..product_len], ident.product_name[0..product_len]);
    const vendor = ident.vendor_id;
    const svc = try c.listServices();
    try testing.expect(svc.capability_flags != 0);
    var services: [32]u8 = undefined;
    const trimmed = svc.trimmedName();
    const svc_len = @min(services.len, trimmed.len);
    @memcpy(services[0..svc_len], trimmed[0..svc_len]);
    const interfaces = try c.listInterfaces();

    // A tag write and read-back, compared value for value.
    var value: [2]u8 = undefined;
    std.mem.writeInt(i16, &value, -1234, .little);
    var write_path: [64]u8 = undefined;
    const elem5 = try std.fmt.bufPrint(&write_path, "{s}[5]", .{tag});
    try c.writeTag(elem5, .int, 1, &value);
    const back = try c.readTag(elem5, 1);
    try testing.expectEqual(DataType.int, back.type);
    try testing.expectEqual(@as(i64, -1234), (try back.at(0)).asInt().?);

    // An array read, so the element-count path runs against a real target.
    var array_path: [64]u8 = undefined;
    const elem0 = try std.fmt.bufPrint(&array_path, "{s}[0]", .{tag});
    const four = try c.readTag(elem0, 4);
    try testing.expectEqual(@as(?usize, 4), four.elementCount());

    // A fragmented read of the same tag, which is a different service.
    var frag_out: [512]u8 = undefined;
    const frag = try c.readTagFragmented(elem0, 10, &frag_out);
    try testing.expectEqual(DataType.int, frag.type);
    try testing.expect(frag.data.len >= 20);

    // A Multiple Service Packet batching two real tags.
    var dint_path: [64]u8 = undefined;
    const dint0 = try std.fmt.bufPrint(&dint_path, "{s}[0]", .{dint_tag});
    const names = [_][]const u8{ elem0, dint0 };
    var results: [2]?TagData = undefined;
    const got = try c.readTags(&names, &results);
    try testing.expectEqual(@as(usize, 2), got);
    try testing.expect(results[0] != null);
    const first_type = results[0].?.type;
    const second_ok = results[1] != null;

    // A tag that does not exist: a real refusal from a real target.
    const missing = c.readTag("ThisTagDoesNotExistAnywhere", 1);
    try testing.expect(std.meta.isError(missing));

    std.debug.print(
        "live ENIP: session=0x{X:0>8} vendor={d} product=\"{s}\" services=\"{s}\" interfaces={d} " ++
            "tag_rw=ok array={d} fragmented={d}B batched_first={t} batched_second_ok={} missing_tag=refused\n",
        .{
            session,
            vendor,
            product[0..product_len],
            services[0..svc_len],
            interfaces,
            four.elementCount().?,
            frag.data.len,
            first_type,
            second_ok,
        },
    );

    try c.unregisterSession();
}

// Set ENIP_TEST_CONNECTED=host:port to run the connected-messaging path
// against a live target. Separate from the test above because not every
// target implements Forward_Open.
test "live: a Class 3 connection against a real target" {
    const endpoint = envVar("ENIP_TEST_CONNECTED") orelse {
        if (verboseSkip()) std.debug.print(
            "SKIPPED: live EtherNet/IP connected messaging (set ENIP_TEST_CONNECTED=host:port)\n",
            .{},
        );
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;
    const tag = envVar("ENIP_TEST_TAG") orelse "SCADA";

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var tt = TcpTransport.connect(io, addr) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live connected messaging (cannot connect to {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer tt.close();
    tt.setReadTimeout(3000);

    var buf: [16384]u8 = undefined;
    var c = try Client.init(tt.transport(), &buf, .{
        .routing = if (directRouting()) .direct else .{ .unconnected_send = &connmgr.backplane_slot_0 },
    });
    _ = try c.registerSession();

    const conn = try c.forwardOpen(.{ .size = 500, .connection_serial = 0x4242 });
    var req_buf: [128]u8 = undefined;
    var path: [64]u8 = undefined;
    const elem0 = try std.fmt.bufPrint(&path, "{s}[0]", .{tag});
    const read = try client.encodeReadTag(elem0, 2, &req_buf);
    var exchanges: usize = 0;
    for (0..3) |_| {
        const reply = try c.sendConnectedCip(read);
        try testing.expect(reply.general_status.hasData());
        const td = try types.TagData.decode(reply.data);
        try testing.expectEqual(DataType.int, td.type);
        exchanges += 1;
    }
    try c.forwardClose();
    std.debug.print(
        "live ENIP connected: o_to_t=0x{X:0>8} t_to_o=0x{X:0>8} exchanges={d} closed=ok\n",
        .{ conn.o_to_t_id, conn.t_to_o_id, exchanges },
    );
    try c.unregisterSession();
}

// Set ENIP_TEST_LISTEN=host:port and point a real EtherNet/IP client at it.
// Without the variable the test prints SKIPPED.
test "live: a real EtherNet/IP client against our adapter" {
    const endpoint = envVar("ENIP_TEST_LISTEN") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live EtherNet/IP adapter (set ENIP_TEST_LISTEN=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var listener = addr.listen(io, .{ .reuse_address = true }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live EtherNet/IP adapter (cannot bind {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer listener.socket.close(io);
    std.debug.print("live ENIP adapter listening on {s}\n", .{endpoint});

    var scada: [200]u8 = @splat(0);
    var dint: [40]u8 = @splat(0);
    var real: [20]u8 = @splat(0);
    std.mem.writeInt(i16, scada[0..2], 1, .little);
    std.mem.writeInt(i32, dint[0..4], 11, .little);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);

    var in: [8192]u8 = undefined;
    var out: [8192]u8 = undefined;
    var connections: usize = 0;
    // Several clients in a row, so a driver that reconnects per operation is
    // served too.
    var accepted: usize = 0;
    while (accepted < 8) : (accepted += 1) {
        const stream = listener.accept(io) catch break;
        var tt = TcpTransport.fromStream(io, stream);
        tt.setReadTimeout(5000);
        const t = tt.transport();
        var rounds: usize = 0;
        while (rounds < 2000) : (rounds += 1) {
            const n = t.read(&in) catch break;
            if (n == 0) continue;
            const reply = target.handle(in[0..n], &out) catch continue;
            const r = reply orelse continue;
            t.write(r) catch break;
        }
        tt.close();
        for (target.connections) |cc| {
            if (cc.o_to_t_id != 0) connections += 1;
        }
        if (target.reads > 0 and target.writes > 0) break;
    }
    std.debug.print(
        "live ENIP adapter: identity={d} reads={d} writes={d} scada[0]={d} connections_seen={d}\n",
        .{
            target.identity_requests,
            target.reads,
            target.writes,
            std.mem.readInt(i16, scada[0..2], .little),
            connections,
        },
    );
    try testing.expect(target.reads > 0);
}

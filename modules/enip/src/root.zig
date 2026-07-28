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
fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

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

fn fuzzAdapter(_: void, smith: *std.testing.Smith) !void {
    var scada: [32]u8 = @splat(0);
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
    var out: [2048]u8 = undefined;
    const reply = target.handle(input[0..len], &out) catch return;
    const r = reply orelse return;
    // Anything the adapter emits must itself be a legal message.
    const msg = try encap.decode(r);
    try testing.expectEqual(r.len, msg.total_len);
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

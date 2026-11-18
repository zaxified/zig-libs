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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "EtherNet/IP + CIP — encapsulation layer (register/SendRRData/SendUnitData), CIP messaging, connection manager, tag/symbolic path client for Logix controllers",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    // The codecs, the client's logic and the adapter are pure computation;
    // only the optional TcpTransport/UdpDiscovery adapters touch std.Io.net.
    .targets = .{.linux64},
    .platform = .any,
    .role = .both, // client + adapter
    // One Client/Adapter owns one connection's buffers, session handle and
    // sequence counters; nothing shared or global. Concurrency is the
    // caller's.
    .concurrency = .single_owner,
    .model_after = "ODVA CIP Volume 1 (Common Industrial Protocol) + Volume 2 (EtherNet/IP Adaptation); wire behaviour cross-checked against captured traffic between independent third-party stacks, and the ConnectionParameters reserved-bit layout against Wireshark's CIP dissector source (GPL-2.0, design reference only — see README Provenance and SPEC.md)",
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
/// The standard objects the adapter serves (TCP/IP Interface, Ethernet Link).
pub const stdobj = @import("stdobj.zig");
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
    _ = stdobj;
    _ = transport;
    _ = client;
    _ = adapter;
    _ = goldens;
}

// ── tests: the whole stack, client against adapter ─────────────────────────

const testing = std.testing;
const fz = @import("fuzz_test.zig");

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
    const name = try c.getAttributeSingle(@backingInt(ClassCode.identity), 1, 7);
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
        reqs[i] = cip.getAttributesAll(@backingInt(cip.ClassCode.identity), 1, &storage[i]) catch unreachable;
    }
    var payload_buf: [1024]u8 = undefined;
    const payload = cip.MultipleService.encode(&reqs, &payload_buf) catch unreachable;

    var path_buf: [16]u8 = undefined;
    const router_path = epath.logicalPath(
        @backingInt(cip.ClassCode.message_router),
        1,
        null,
        &path_buf,
    ) catch unreachable;
    var wire_buf: [2048]u8 = undefined;
    const wire = (cip.Request{
        .service = @backingInt(cip.Service.multiple_service_packet),
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

/// A `Write Tag` of one INT, as a bare CIP request.
fn encodeWriteInt(name: []const u8, value: i16, out: []u8) ![]const u8 {
    var path_buf: [64]u8 = undefined;
    const path = try tagpath.encodePath(name, &path_buf);
    var v: [2]u8 = undefined;
    std.mem.writeInt(i16, &v, value, .little);
    var data_buf: [16]u8 = undefined;
    const data = try (types.WriteTagRequest{ .type = .int, .count = 1, .values = &v }).encode(&data_buf);
    return (cip.Request{ .service = cip.LogixService.write_tag, .path = path, .data = data }).encode(out);
}

/// Wraps already-encoded requests in a `Multiple_Service_Packet` addressed
/// to the Message Router.
fn encodeBatch(reqs: []const []const u8, payload_buf: []u8, out: []u8) ![]u8 {
    const payload = try cip.MultipleService.encode(reqs, payload_buf);
    var path_buf: [16]u8 = undefined;
    const router_path = try epath.logicalPath(@backingInt(cip.ClassCode.message_router), 1, null, &path_buf);
    return (cip.Request{
        .service = @backingInt(cip.Service.multiple_service_packet),
        .path = router_path,
        .data = payload,
    }).encode(out);
}

test "a multiple service packet with a bad offset table executes none of its requests" {
    // Review 2026-10-06. `MultipleService.at(i)` validates entry `i` and
    // `i + 1` only, and the adapter used to validate lazily — so a write in
    // entry 0 was APPLIED, and then entry 1's out-of-range end offset turned
    // the whole packet into `invalid_parameter_value`. The originator reads
    // that as "nothing happened" while the tag has changed.
    var scada: [200]u8 = @splat(0);
    var dint: [40]u8 = @splat(0);
    var real: [20]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);

    var w_buf: [64]u8 = undefined;
    var g_buf: [32]u8 = undefined;
    const write = try encodeWriteInt("SCADA[0]", 0x1234, &w_buf);
    const get = try cip.getAttributesAll(@backingInt(cip.ClassCode.identity), 1, &g_buf);
    var payload_buf: [256]u8 = undefined;
    var wire_buf: [512]u8 = undefined;
    const wire = try encodeBatch(&.{ write, get, get }, &payload_buf, &wire_buf);
    // Request header: service, path size, the 4-octet router path; then the
    // payload: count (2), offsets (3 x 2). Point the THIRD offset past the end.
    const table = 2 + 4 + 2;
    std.mem.writeInt(u16, wire[table + 4 ..][0..2], 0xFFFF, .little);

    var out: [4096]u8 = undefined;
    const reply = try cip.Reply.decode(try target.messageRouter(wire, &out));
    try testing.expectEqual(cip.GeneralStatus.invalid_parameter_value, reply.general_status);
    try testing.expectEqual(@as(i16, 0), std.mem.readInt(i16, scada[0..2], .little));
    try testing.expectEqual(@as(usize, 0), target.writes);
}

test "a multiple service packet whose replies overflow is answered per request, not dropped after its writes" {
    // Review 2026-10-06. Embedded replies were built into a fixed 4096-octet
    // scratch with no budget for the table, the reply header or the replies
    // still to come. A batch of reads of a large-enough tag ran it dry, the
    // overflow surfaced as `error.BufferTooSmall` out of `Adapter.handle` —
    // no reply at all — AFTER an earlier write in the same batch had been
    // applied. Any client on the listening socket can send that batch.
    var scada: [200]u8 = @splat(0);
    var big: [1024]u8 = @splat(0x11);
    var real: [20]u8 = @splat(0);
    var tags = [_]TagBinding{
        .{ .name = "SCADA", .type = .int, .bytes = &scada },
        .{ .name = "Big", .type = .sint, .bytes = &big },
        .{ .name = "RealTag", .type = .real, .bytes = &real },
    };
    var target = Adapter.init(.{}, &tags);
    var paired = PairedTransport{ .target = &target };
    var buf: [16384]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();

    var w_buf: [64]u8 = undefined;
    var r_buf: [64]u8 = undefined;
    const write = try encodeWriteInt("SCADA[0]", 77, &w_buf);
    const read = try client.encodeReadTag("Big[0]", big.len, &r_buf);
    const reqs = [_][]const u8{ write, read, read, read, read, read };
    var replies: [reqs.len]cip.Reply = undefined;
    try testing.expectEqual(reqs.len, try c.multipleServices(&reqs, &replies));
    try testing.expectEqual(@as(usize, 0), paired.failures);

    // The write happened and says so.
    try testing.expectEqual(@as(i16, 77), std.mem.readInt(i16, scada[0..2], .little));
    try testing.expect(replies[0].general_status.isSuccess());
    // Every read answers for itself: whole, partial, or too large to carry.
    for (replies[1..]) |r| {
        switch (r.general_status) {
            .success, .partial_transfer => {
                const td = try types.TagData.decode(r.data);
                try testing.expectEqual(DataType.sint, td.type);
            },
            .reply_data_too_large => {},
            else => return error.TestUnexpectedResult,
        }
    }
    try testing.expect(replies[1].general_status.isSuccess());
}

test "a member index whose octet offset overflows usize is refused, not a panic" {
    // Review 2026-10-06. `pathElement(path) * esize + byte_offset` and
    // `start + values.len` were unchecked; the member id is a peer-supplied
    // u32, so on a 32-bit target `0xFFFF_FFFF * 4` overflowed `usize` and
    // trapped. Exercised as RED with `-Dtarget=x86-linux-musl`.
    var scada: [200]u8 = @splat(0);
    var dint: [40]u8 = @splat(0);
    var real: [20]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);

    var path_buf: [32]u8 = undefined;
    var b = epath.Builder.init(&path_buf);
    try b.symbol("TestTag");
    try b.member(0xFFFF_FFFF);
    var out: [256]u8 = undefined;

    var rq_buf: [64]u8 = undefined;
    var rd: [6]u8 = undefined;
    const rdata = try (types.ReadTagFragmentedRequest{ .count = 1, .byte_offset = 0xFFFF_FFFF }).encode(&rd);
    const rreq = try (cip.Request{ .service = cip.LogixService.read_tag_fragmented, .path = b.bytes(), .data = rdata }).encode(&rq_buf);
    const rrep = try cip.Reply.decode(try target.messageRouter(rreq, &out));
    try testing.expectEqual(cip.GeneralStatus.invalid_parameter_value, rrep.general_status);

    var wq_buf: [64]u8 = undefined;
    var wd: [16]u8 = undefined;
    const v = [_]u8{ 1, 2, 3, 4 };
    const wdata = try (types.WriteTagFragmentedRequest{ .type = .dint, .count = 1, .byte_offset = 0xFFFF_FFFF, .values = &v }).encode(&wd);
    const wreq = try (cip.Request{ .service = cip.LogixService.write_tag_fragmented, .path = b.bytes(), .data = wdata }).encode(&wq_buf);
    const wrep = try cip.Reply.decode(try target.messageRouter(wreq, &out));
    try testing.expectEqual(cip.GeneralStatus.too_much_data, wrep.general_status);
    try testing.expectEqual(@as(usize, 0), target.writes);
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
    b.class(@backingInt(cip.ClassCode.message_router)) catch unreachable;
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
        @as(u16, @backingInt(connmgr.ExtendedStatus.connection_not_found)),
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
    b.class(@backingInt(cip.ClassCode.message_router)) catch unreachable;
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
        @as(u16, @backingInt(connmgr.ExtendedStatus.connection_limit_reached)),
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
    try testing.expectError(error.CipError, c.reset(@backingInt(ClassCode.identity), 1));
    try testing.expect(!target.reset_requested);

    var allowed = Adapter.init(.{ .allow_reset = true }, &tags);
    var paired2 = PairedTransport{ .target = &allowed };
    var buf2: [8192]u8 = undefined;
    var c2 = try Client.init(paired2.seam(), &buf2, .{ .routing = .direct });
    _ = try c2.registerSession();
    try c2.reset(@backingInt(ClassCode.identity), 1);
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
        @backingInt(cip.ClassCode.symbol),
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
    const path = try epath.logicalPath(@backingInt(cip.ClassCode.symbol), 0, null, &path_buf);
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
    const path = try epath.logicalPath(@backingInt(cip.ClassCode.identity), 0, null, &path_buf);
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
    const class = @backingInt(cip.ClassCode.program_name);

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
    try pb.class(@backingInt(cip.ClassCode.symbol));
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
    try mb.class(@backingInt(cip.ClassCode.symbol));
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
        &([_]u8{ 0x6F, 0x00, 0xFF, 0x00 } ++ @as([20]u8, @splat(0))),
        // SendRRData with an empty body.
        &([_]u8{ 0x6F, 0x00, 0x00, 0x00 } ++ @as([20]u8, @splat(0))),
        // A CPF item count that overruns.
        &([_]u8{ 0x6F, 0x00, 0x08, 0x00 } ++ @as([20]u8, @splat(0)) ++
            [_]u8{ 0, 0, 0, 0, 0, 0, 0xFF, 0xFF }),
        // An unknown command.
        &([_]u8{ 0x34, 0x12, 0x00, 0x00 } ++ @as([20]u8, @splat(0))),
    };
    for (hostile) |h| {
        _ = target.handle(h, &out) catch continue;
    }
}

/// A `Smith` seed for `fuzzAdapter`: the message behind the little-endian u32
/// length header `Smith.slice` reads, then the eight octets the session-open
/// draw consumes as a little-endian u64.
///
/// ⚠ The array has to be static; a `const` local here is not promoted and the
/// slice comes back dangling with the right length and garbage behind it.
fn fuzzAdapterSeed(comptime h: []const u8, comptime session_open: bool) []const u8 {
    return &struct {
        const f = blk: {
            @setEvalBranchQuota(40_000);
            var out: [h.len / 2]u8 = undefined;
            for (&out, 0..) |*b, i| b.* = std.fmt.parseInt(u8, h[i * 2 ..][0..2], 16) catch unreachable;
            break :blk out;
        };
        const bytes = std.mem.toBytes(@as(u32, @intCast(f.len))) ++ f ++
            std.mem.toBytes(@as(u64, if (session_open) 1 else 0));
    }.bytes;
}

/// Whole encapsulation messages as an adapter receives them, each run once with
/// the session already open and once without — which is what the
/// `boolWeighted` draw was there to arrange and could not.
const adapter_seeds = [_][]const u8{
    fuzzAdapterSeed("630000000000000000000000000000000000000000000000", false), // ListIdentity
    fuzzAdapterSeed("040000000000000000000000000000000000000000000000", false), // ListServices
    fuzzAdapterSeed("65000400000000000000000000000000000000000000000001000000", false), // RegisterSession
    fuzzAdapterSeed("660000000100a5a500000000000000000000000000000000", true), // UnregisterSession
    fuzzAdapterSeed("6f0016000100a5a50000000000000000000000000000000000000000e803020000000000b20006004c0220062401", true), // SendRRData, session open
    fuzzAdapterSeed("6f0016000100a5a50000000000000000000000000000000000000000e803020000000000b20006004c0220062401", false), // ... and closed
    fuzzAdapterSeed("6f001d000100a5a50000000000000000000000000000000000000000e803020000000000b2000d004c03910553434144410001000100", true), // Read Tag "SCADA"
    fuzzAdapterSeed("700016000100a5a50000000000000000000000000000000000000000e803020000000000b20006004c0220062401", true), // SendUnitData
    fuzzAdapterSeed("6f0000000100a5a500000000000000000000000000000000", true), // SendRRData with no body
    fuzzAdapterSeed("6f000e0000000000000000000000000000000000000000000000000000000800000000000000", true), // a CPF count that overruns
    fuzzAdapterSeed("341200000000000000000000000000000000000000000000", false), // an unknown command
    fuzzAdapterSeed("6f0008000000000000000000", false), // shorter than the header
};

test "fuzz: the adapter never panics on arbitrary messages" {
    try std.testing.fuzz({}, fuzzAdapterSmith, .{ .corpus = &adapter_seeds });
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

const fuzzAdapterMark = fz.Marker(enum { ran, nonempty });

fn fuzzAdapterSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzAdapter(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzAdapter(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var scada: [fuzz_scada_len]u8 = @splat(0);
    var dint: [16]u8 = @splat(0);
    var real: [16]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);

    var input: [1024]u8 = undefined;
    // ⚠ The message is drawn FIRST, with one `smith.slice` call. It used to be
    // `smith.bytes(&input)` followed by `smith.valueRangeAtMost(u16, 0, ...)`,
    // behind a `smith.boolWeighted(1, 1)`. Both of those are ranged draws, and
    // a `Smith` ranged draw returns the range MINIMUM unless the eight octets
    // it reads as a little-endian u64 already lie inside the range: the
    // `boolWeighted` was `false` on every run, so the "half the runs start with
    // a session already open" the comment promised was NONE of them, and the
    // length was 0, so the adapter was handed the empty message. Measured on
    // 2026-09-06 over the corpus above: **0 of 12 non-empty, 0 replies, and the
    // session never open before; 12 of 12 non-empty, 9 replies, and the session
    // open on 6 of the 12 after.**
    const len: usize = fz.drawInput(S, src, &input, &adapter_seeds);
    fuzzAdapterMark.mark(.ran);
    if (len != 0) fuzzAdapterMark.mark(.nonempty);
    // The session flag follows the message, drawn with a full-width `value`.
    if (src.value(u64) & 1 == 1) target.session_handle = 0xA5A5_0001;
    var out: [fuzz_out_len]u8 = undefined;
    const reply = target.handle(input[0..len], &out) catch return;
    const r = reply orelse return;
    // Anything the adapter emits must itself be a legal message.
    const msg = try encap.decode(r);
    try testing.expectEqual(r.len, msg.total_len);
}

test "fuzz driver: ENIP_FUZZ (fuzzAdapter)" {
    try fz.fuzz_driver.run(fuzzAdapter, .{ .prefix = "ENIP_FUZZ", .name = "enip-root-adapter" });
}

test "fuzz harness: fuzzAdapter, 400 seeds, reaches every outcome" {
    try fuzzAdapterMark.reach(fuzzAdapter, "enip-root-adapter", 400);
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

/// Encapsulation replies as a client receives them. Every entry is at least
/// the 24-octet header, because the harness rewrites the header anyway and a
/// shorter draw would be padded back up to 24.
const client_reply_seeds = [_][]const u8{
    fuzzAdapterSeed("6f001d000100a5a50000000000000000000000000000000000000000e803020000000000b2000d00cc000000c401000002000000", false)[4..],
    fuzzAdapterSeed("6f0016000100a5a50000000000000000000000000000000000000000e803020000000000b20006004c0220062401", false)[4..],
    fuzzAdapterSeed("6f0000000100a5a500000000000000000000000000000000", false)[4..],
    fuzzAdapterSeed("6f000e0000000000000000000000000000000000000000000000000000000800000000000000", false)[4..],
    fuzzAdapterSeed("6f0010000100a5a5000000000000000000000000000000000000000000000000010000000000", false)[4..],
    fuzzAdapterSeed("6f0038000100a5a50000000000000000000000000000000000000000e803ffff0000000000b2002e00cc0001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021", false)[4..],
};

test "fuzz: a client survives an arbitrary reply without panicking" {
    try std.testing.fuzz({}, fuzzClientReplySmith, .{ .corpus = &client_reply_seeds });
}

const fuzzClientReplyMark = fz.Marker(enum { ran, nonempty });

fn fuzzClientReplySmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzClientReply(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzClientReply(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var lt: transport.LoopTransport = .{};
    var reply: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length. The
    // ranged draw here had a MINIMUM of 24, not 0, so the collapse was quieter
    // than most: `len` was 24 on every run and the client was fed a bare
    // header with an empty body, forever. Measured on 2026-09-06 over the
    // corpus above: **`len` was 24 on every one of the six
    // seeds before — a header and nothing else; after, it is 28, 42, 42, 50, 56
    // and 82, so the CPF body reaches the reply decoder for the first time.**
    const len: usize = @max(24, fz.drawInput(S, src, &reply, &client_reply_seeds));
    fuzzClientReplyMark.mark(.ran);
    if (len != 0) fuzzClientReplyMark.mark(.nonempty);
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

test "fuzz driver: ENIP_FUZZ (fuzzClientReply)" {
    try fz.fuzz_driver.run(fuzzClientReply, .{ .prefix = "ENIP_FUZZ", .name = "enip-root-clientReply" });
}

test "fuzz harness: fuzzClientReply, 400 seeds, reaches every outcome" {
    try fuzzClientReplyMark.reach(fuzzClientReply, "enip-root-clientReply", 400);
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
    const colon = std.mem.findScalarLast(u8, endpoint, ':') orelse return null;
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
    const elem5 = try std.mem.print(&write_path, "{s}[5]", .{tag});
    try c.writeTag(elem5, .int, 1, &value);
    const back = try c.readTag(elem5, 1);
    try testing.expectEqual(DataType.int, back.type);
    try testing.expectEqual(@as(i64, -1234), (try back.at(0)).asInt().?);

    // An array read, so the element-count path runs against a real target.
    var array_path: [64]u8 = undefined;
    const elem0 = try std.mem.print(&array_path, "{s}[0]", .{tag});
    const four = try c.readTag(elem0, 4);
    try testing.expectEqual(@as(?usize, 4), four.elementCount());

    // A fragmented read of the same tag, which is a different service.
    var frag_out: [512]u8 = undefined;
    const frag = try c.readTagFragmented(elem0, 10, &frag_out);
    try testing.expectEqual(DataType.int, frag.type);
    try testing.expect(frag.data.len >= 20);

    // A Multiple Service Packet batching two real tags.
    var dint_path: [64]u8 = undefined;
    const dint0 = try std.mem.print(&dint_path, "{s}[0]", .{dint_tag});
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
    const elem0 = try std.mem.print(&path, "{s}[0]", .{tag});
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
    // ENIP_TEST_STDOBJ=1 serves the configuration the standard-object goldens
    // were captured against (TCP/IP Interface values and Set enabled).
    var live_cfg: AdapterConfig = .{};
    if (envVar("ENIP_TEST_STDOBJ") != null) {
        live_cfg = tcpip_cfg;
        live_cfg.allow_tcpip_set = true;
    }
    // ENIP_TEST_ASM=1 serves the Assembly instances the assembly goldens were
    // captured against: 100 (4 octets, read-only), 150 (3 octets, writable).
    var asm_in = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
    var asm_out = [3]u8{ 0, 0, 0 };
    const asm_list = [_]stdobj.Assembly{
        .{ .instance = 100, .data = &asm_in },
        .{ .instance = 150, .data = &asm_out, .writable = true },
    };
    if (envVar("ENIP_TEST_ASM") != null) live_cfg.assemblies = &asm_list;
    var target = Adapter.init(live_cfg, &tags);

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

// ── whole-module mutation audit 2026-11-17: boundary tests ────────────────
//
// A transport between a client and an adapter (or canned frames) that records
// what the client wrote and can rewrite or trickle what it reads back.

const Tap = struct {
    target: ?*Adapter = null,
    canned: []const []const u8 = &.{},
    rewrite: ?*const fn (*Tap, []u8) []u8 = null,
    trickle: usize = 0,
    out: [8192]u8 = undefined,
    scratch: [8192]u8 = undefined,
    queue: [16384]u8 = undefined,
    queue_len: usize = 0,
    queue_pos: usize = 0,
    last: [4096]u8 = undefined,
    last_len: usize = 0,
    lens: [32]usize = @splat(0),
    writes: usize = 0,

    fn seam(self: *Tap) Transport {
        return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
    }

    fn lastFrame(self: *const Tap) []const u8 {
        return self.last[0..self.last_len];
    }

    fn readFn(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const self: *Tap = @ptrCast(@alignCast(ctx));
        const avail = self.queue_len - self.queue_pos;
        if (avail == 0) return 0;
        var n = @min(avail, buf.len);
        if (self.trickle != 0) n = @min(n, self.trickle);
        @memcpy(buf[0..n], self.queue[self.queue_pos..][0..n]);
        self.queue_pos += n;
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *Tap = @ptrCast(@alignCast(ctx));
        const n = @min(bytes.len, self.last.len);
        @memcpy(self.last[0..n], bytes[0..n]);
        self.last_len = n;
        if (self.writes < self.lens.len) self.lens[self.writes] = bytes.len;
        defer self.writes += 1;
        var reply: ?[]const u8 = null;
        if (self.target) |t| {
            reply = t.handle(bytes, &self.out) catch null;
        } else if (self.canned.len > 0) {
            reply = self.canned[@min(self.writes, self.canned.len - 1)];
        }
        var r = reply orelse return;
        if (self.rewrite) |f| {
            @memcpy(self.scratch[0..r.len], r);
            r = f(self, self.scratch[0..r.len]);
        }
        if (self.queue_len + r.len > self.queue.len) return error.WriteFailed;
        @memcpy(self.queue[self.queue_len..][0..r.len], r);
        self.queue_len += r.len;
    }
};

fn tapFrame(cmd: encap.Command, session: u32, data: []const u8, out: []u8) []const u8 {
    return encap.encode(.{
        .command = cmd,
        .session_handle = session,
        .status = .success,
        .sender_context = @splat(0),
        .options = 0,
        .data = data,
        .total_len = 0,
    }, out) catch unreachable;
}

fn cipReplyOf(service: u8, status: cip.GeneralStatus, data: []const u8, out: []u8) []const u8 {
    return (cip.Reply{ .service = service, .general_status = status, .additional_status = &.{}, .data = data }).encode(out) catch unreachable;
}

fn rrItemsReply(session: u32, items: []const cpf.Item, out: []u8) []const u8 {
    var env: [2048]u8 = undefined;
    const e = cpf.encodeEnvelope(0, 0, items, &env) catch unreachable;
    return tapFrame(.send_rr_data, session, e, out);
}

fn rrCanned(session: u32, cip_reply: []const u8, out: []u8) []const u8 {
    const items = cpf.unconnectedItems(cip_reply);
    return rrItemsReply(session, &items, out);
}

fn lastCip(t: *const Tap, storage: *[8]cpf.Item) !cip.Request {
    const msg = try encap.decode(t.lastFrame());
    const env = try cpf.decodeEnvelope(msg.data, storage);
    return cip.Request.decode(env.list.dataItem().?.data);
}

fn cannedClient(tap: *Tap, buf: []u8) !Client {
    var c = try Client.init(tap.seam(), buf, .{ .routing = .direct });
    c.registered = true;
    c.session_handle = 0x55;
    return c;
}

fn rwCommand(_: *Tap, r: []u8) []u8 {
    r[0] = 4;
    r[1] = 0;
    return r;
}

fn rwSession(_: *Tap, r: []u8) []u8 {
    r[4] ^= 0x55;
    return r;
}

fn rwVersion(_: *Tap, r: []u8) []u8 {
    r[24] = 2;
    return r;
}

fn rwHuge(_: *Tap, r: []u8) []u8 {
    std.mem.writeInt(u16, r[2..4], 1001, .little);
    return r[0..24];
}

fn rwHugeShort(_: *Tap, r: []u8) []u8 {
    std.mem.writeInt(u16, r[2..4], 1001, .little);
    return r[0..10];
}

fn rwExact(t: *Tap, r: []u8) []u8 {
    _ = r;
    @memset(t.scratch[24..1024], 0);
    std.mem.writeInt(u16, t.scratch[2..4], 1000, .little);
    return t.scratch[0..1024];
}

test "client init: the smallest accepted buffer and how it is split" {
    var tap = Tap{};
    var small: [2047]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, Client.init(tap.seam(), &small, .{}));
    var exact: [2048]u8 = undefined;
    const c = try Client.init(tap.seam(), &exact, .{});
    try testing.expectEqual(@as(usize, 1024), c.tx.len);
    try testing.expectEqual(@as(usize, 1024), c.rx.len);
}

test "client frames carry the context and the session, and unregister resets the client" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var tap = Tap{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct, .sender_context = "ctx-test".*, .encapsulation_timeout = 7 });
    try c.unregisterSession();
    try testing.expectEqual(@as(usize, 0), tap.writes);
    const h = try c.registerSession();
    try testing.expectEqualSlices(u8, "ctx-test", tap.last[12..20]);
    try c.nop();
    const nopm = try encap.decode(tap.lastFrame());
    try testing.expectEqual(Command.nop, nopm.command);
    try testing.expectEqual(h, nopm.session_handle);
    try testing.expectEqualSlices(u8, "ctx-test", &nopm.sender_context);
    _ = try c.getAttributeSingle(1, 1, 1);
    const rr = try encap.decode(tap.lastFrame());
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, rr.data[0..4], .little));
    try testing.expectEqual(@as(u16, 7), std.mem.readInt(u16, rr.data[4..6], .little));
    c.connection = .{ .o_to_t_id = 1, .t_to_o_id = 2, .serial = 3, .size = 4 };
    try c.unregisterSession();
    const un = try encap.decode(tap.lastFrame());
    try testing.expectEqual(Command.unregister_session, un.command);
    try testing.expectEqual(h, un.session_handle);
    try testing.expectEqualSlices(u8, "ctx-test", &un.sender_context);
    try testing.expect(!c.registered);
    try testing.expectEqual(@as(u32, 0), c.session_handle);
    try testing.expectEqual(@as(?Connection, null), c.connection);
}

test "client: a reply delivered a few octets at a time is reassembled" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var tap = Tap{ .target = &target, .trickle = 5 };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    const id = try c.listIdentity();
    try testing.expectEqualStrings("zig-enip adapter", id.product_name);
}

test "client: refusals at the encapsulation layer" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var tap = Tap{ .target = &target };
    var buf: [2048]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    // The adapter answers a message in an unknown session with a header-only error reply.
    const handle = target.session_handle;
    target.session_handle = 0;
    try testing.expectError(error.EncapsulationError, c.getAttributeSingle(1, 1, 1));
    target.session_handle = handle;
    tap.rewrite = rwCommand;
    try testing.expectError(error.UnexpectedCommand, c.listIdentity());
    tap.rewrite = rwSession;
    try testing.expectError(error.SessionMismatch, c.getAttributeSingle(1, 1, 1));
    // The list commands are sessionless: their reply's handle is not compared.
    _ = try c.listIdentity();
    tap.rewrite = rwHuge;
    try testing.expectError(error.BufferTooSmall, c.listIdentity());
    // Only ten octets of the header ever arrive: the message is never complete, whatever its length says.
    tap.rewrite = rwHugeShort;
    try testing.expectError(error.ReadFailed, c.listIdentity());
    tap.rewrite = rwExact;
    try testing.expectError(error.BadReply, c.listIdentity());
    tap.rewrite = null;
    var c2 = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    tap.rewrite = rwVersion;
    try testing.expectError(error.BadReply, c2.registerSession());
}

test "client: ListInterfaces counts the items it was given" {
    var cb: [64]u8 = undefined;
    const two = [_]cpf.Item{ .{ .type_id = .null_address, .data = &.{} }, .{ .type_id = .null_address, .data = &.{} } };
    const list = cpf.encode(&two, &cb) catch unreachable;
    var fb: [128]u8 = undefined;
    const reps = [_][]const u8{tapFrame(.list_interfaces, 0, list, &fb)};
    var tap = Tap{ .canned = &reps };
    var buf: [2048]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    try testing.expectEqual(@as(usize, 2), try c.listInterfaces());
}

fn unitReply(session: u32, seq: u16, first_unconnected: bool, out: []u8) []const u8 {
    var rep: [32]u8 = undefined;
    const cr = cipReplyOf(0x0E, .success, &.{ 1, 2 }, &rep);
    var cd: [64]u8 = undefined;
    const body = cpf.ConnectedData.encode(seq, cr, &cd) catch unreachable;
    const id = [4]u8{ 0x22, 0, 0, 0 };
    var items = cpf.connectedItems(&id, body);
    if (first_unconnected) items[0] = .{ .type_id = .unconnected_data, .data = &.{} };
    var env: [128]u8 = undefined;
    const e = cpf.encodeEnvelope(0, 0, &items, &env) catch unreachable;
    return tapFrame(.send_unit_data, session, e, out);
}

test "client: a connected reply is checked for order, sequence and session" {
    const req = [_]u8{ 0x0E, 2, 0x20, 1, 0x24, 1 };
    var f1: [256]u8 = undefined;
    var f2: [256]u8 = undefined;
    var f3: [256]u8 = undefined;
    var f4: [256]u8 = undefined;
    var buf: [2048]u8 = undefined;
    {
        const reps = [_][]const u8{unitReply(0x55, 1, false, &f1)};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        c.connection = .{ .o_to_t_id = 0x11, .t_to_o_id = 0x22, .serial = 1, .size = 500 };
        const r = try c.sendConnectedCip(&req);
        try testing.expectEqualSlices(u8, &.{ 1, 2 }, r.data);
        try testing.expectEqual(@as(u16, 1), c.connection.?.sequence);
        // The frame went out with sequence count 1 on the originator-to-target id.
        const msg = try encap.decode(tap.lastFrame());
        var st: [8]cpf.Item = undefined;
        const env = try cpf.decodeEnvelope(msg.data, &st);
        try testing.expectEqual(@as(u32, 0x11), try cpf.connectionId(env.list.addressItem().?));
        try testing.expectEqual(@as(u16, 1), (try cpf.ConnectedData.decode(env.list.dataItem().?)).sequence_count);
    }
    {
        const reps = [_][]const u8{unitReply(0x55, 2, false, &f2)};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        c.connection = .{ .o_to_t_id = 0x11, .t_to_o_id = 0x22, .serial = 1, .size = 500 };
        try testing.expectError(error.SequenceMismatch, c.sendConnectedCip(&req));
    }
    {
        const reps = [_][]const u8{unitReply(0x55, 1, true, &f3)};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        c.connection = .{ .o_to_t_id = 0x11, .t_to_o_id = 0x22, .serial = 1, .size = 500 };
        try testing.expectError(error.BadReply, c.sendConnectedCip(&req));
    }
    {
        // Before RegisterSession there is no session to compare the reply's handle with.
        const reps = [_][]const u8{unitReply(0x77, 1, false, &f4)};
        var tap = Tap{ .canned = &reps };
        var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
        c.connection = .{ .o_to_t_id = 0x11, .t_to_o_id = 0x22, .serial = 1, .size = 500 };
        _ = try c.sendConnectedCip(&req);
    }
}

test "client: an unconnected reply must be an address item then an unconnected data item" {
    var rep: [32]u8 = undefined;
    const cr = cipReplyOf(0x0E, .success, &.{ 1, 2 }, &rep);
    const seq8: [8]u8 = @splat(0);
    var f: [3][512]u8 = undefined;
    const good = [_]cpf.Item{ .{ .type_id = .null_address, .data = &.{} }, .{ .type_id = .unconnected_data, .data = cr } };
    const swapped = [_]cpf.Item{ .{ .type_id = .unconnected_data, .data = &.{} }, .{ .type_id = .unconnected_data, .data = cr } };
    const wrong_type = [_]cpf.Item{ .{ .type_id = .sequenced_address, .data = &seq8 }, .{ .type_id = .connected_data, .data = cr } };
    var buf: [2048]u8 = undefined;
    const req = [_]u8{ 0x0E, 2, 0x20, 1, 0x24, 1 };
    {
        const reps = [_][]const u8{rrItemsReply(0x55, &good, &f[0])};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        try testing.expectEqualSlices(u8, &.{ 1, 2 }, (try c.sendCip(&req)).data);
    }
    {
        const reps = [_][]const u8{rrItemsReply(0x55, &swapped, &f[1])};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        try testing.expectError(error.BadReply, c.sendCip(&req));
    }
    {
        const reps = [_][]const u8{rrItemsReply(0x55, &wrong_type, &f[2])};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        try testing.expectError(error.BadReply, c.sendCip(&req));
    }
}

test "client: a direct request that cannot fit the transmit buffer is refused, a routed one is wrapped whole" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var tap = Tap{ .target = &target };
    var buf: [2048]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    const big: [1100]u8 = @splat(0);
    try testing.expectError(error.BufferTooSmall, c.sendCip(&big));

    // Routed: a 300-octet embedded message makes a 314-octet wrapper, which needs the whole front half.
    var c2 = try Client.init(tap.seam(), &buf, .{ .cm_timeout = .{ .priority_time_tick = 0x0A, .timeout_ticks = 3 } });
    c2.registered = true;
    c2.session_handle = c.session_handle;
    const emb: [300]u8 = @splat(0);
    const r = try c2.sendCip(&emb);
    try testing.expectEqual(cip.GeneralStatus.service_not_supported, r.general_status);
    var st: [8]cpf.Item = undefined;
    const req = try lastCip(&tap, &st);
    try testing.expectEqual(@as(u8, connmgr.Service.unconnected_send), req.service);
    const us = try connmgr.UnconnectedSend.decode(req.data);
    try testing.expectEqual(@as(u8, 0x0A), us.timeout.priority_time_tick);
    try testing.expectEqual(@as(u8, 3), us.timeout.timeout_ticks);
}

test "client: a CIP error status is an error for every attribute service, and a partial read is not" {
    var big: [5000]u8 = @splat(1);
    var small: [16]u8 = @splat(0);
    var one: [2]u8 = @splat(0);
    var tags = [_]TagBinding{
        .{ .name = "BIG", .type = .sint, .bytes = &big },
        .{ .name = "SMALL", .type = .dint, .bytes = small[0..8] },
        .{ .name = "STRUCT", .type = .structure, .bytes = &one },
    };
    var target = Adapter.init(.{}, &tags);
    var tap = Tap{ .target = &target };
    var buf: [16384]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    try testing.expectError(error.CipError, c.getAttributeSingle(1, 1, 99));
    try testing.expectError(error.CipError, c.getAttributesAll(5, 1));
    try testing.expectError(error.CipError, c.setAttributeSingle(1, 1, 1, &.{ 1, 0 }));
    // A tag larger than one reply comes back partial, and a plain read accepts that.
    const part = try c.readTag("BIG[0]", 5000);
    try testing.expectEqual(@as(usize, 3992), part.data.len);
    // The fragmented read of a missing tag is an error; of an existing one it reassembles.
    var acc: [6000]u8 = undefined;
    try testing.expectError(error.CipError, c.readTagFragmented("NOPE", 1, &acc));
    const all = try c.readTagFragmented("BIG", 5000, &acc);
    try testing.expectEqual(@as(usize, 5000), all.data.len);
    // Writes: the count the caller gave is the count sent.
    var vals: [6]u8 = @splat(0);
    try c.writeTag("SMALL[0]", .dint, 3, vals[0..4]);
    var st: [8]cpf.Item = undefined;
    const req = try lastCip(&tap, &st);
    try testing.expectEqual(@as(u16, 3), (try types.WriteTagRequest.decode(req.data)).count);
    try testing.expectError(error.CipError, c.writeTag("SMALL[0]", .int, 1, vals[0..2]));
}

test "client: a fragmented write never splits an element and sends the last octet" {
    var sints: [4]u8 = @splat(0);
    var dints: [8]u8 = @splat(0);
    var tags = [_]TagBinding{
        .{ .name = "S", .type = .sint, .bytes = &sints },
        .{ .name = "D", .type = .dint, .bytes = &dints },
    };
    var target = Adapter.init(.{}, &tags);
    var tap = Tap{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    const before = tap.writes;
    try c.writeTagFragmented("S", .sint, 3, &.{ 1, 2, 3 }, 2);
    try testing.expectEqual(@as(usize, 2), tap.writes - before);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 0 }, &sints);
    try testing.expect(tap.lens[before] == tap.lens[before + 1] + 1);
    var st: [8]cpf.Item = undefined;
    const req = try lastCip(&tap, &st);
    try testing.expectEqual(@as(u16, 3), (try types.WriteTagFragmentedRequest.decode(req.data)).count);
    // A chunk of six octets holds one whole DINT, so the fragments are four octets each.
    const b2 = tap.writes;
    try c.writeTagFragmented("D", .dint, 2, &.{ 1, 0, 0, 0, 2, 0, 0, 0 }, 6);
    try testing.expectEqual(@as(usize, 2), tap.writes - b2);
    try testing.expectEqual(tap.lens[b2], tap.lens[b2 + 1]);
    // A chunk smaller than an element still moves one element at a time.
    const b3 = tap.writes;
    try c.writeTagFragmented("D", .dint, 2, &.{ 5, 0, 0, 0, 6, 0, 0, 0 }, 1);
    try testing.expectEqual(@as(usize, 2), tap.writes - b3);
    try testing.expectEqualSlices(u8, &.{ 5, 0, 0, 0, 6, 0, 0, 0 }, &dints);
    try testing.expectError(error.MalformedReply, c.writeTagFragmented("D", .string, 1, &.{ 1, 2 }, 2));
    try testing.expectError(error.CipError, c.writeTagFragmented("D", .int, 2, &.{ 1, 2, 3, 4 }, 4));
}

test "client: a fragmented read follows partial transfers and rejects what is inconsistent" {
    var cb: [3][256]u8 = undefined;
    var fb: [3][512]u8 = undefined;
    var tdb: [64]u8 = undefined;
    var out: [16]u8 = undefined;
    var buf: [2048]u8 = undefined;
    // The type changes between fragments.
    {
        const a = (types.TagData{ .type = .dint, .data = &.{ 1, 2, 3, 4 } }).encode(&tdb) catch unreachable;
        const ra = rrCanned(0x55, cipReplyOf(0x52, .partial_transfer, a, &cb[0]), &fb[0]);
        var tdb2: [64]u8 = undefined;
        const b = (types.TagData{ .type = .int, .data = &.{ 5, 6 } }).encode(&tdb2) catch unreachable;
        const rb = rrCanned(0x55, cipReplyOf(0x52, .success, b, &cb[1]), &fb[1]);
        const reps = [_][]const u8{ ra, rb };
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        try testing.expectError(error.MalformedReply, c.readTagFragmented("T", 4, &out));
    }
    // A fragment that does not fit the caller's buffer.
    {
        const a = (types.TagData{ .type = .dint, .data = &.{ 1, 2, 3, 4 } }).encode(&tdb) catch unreachable;
        const reps = [_][]const u8{rrCanned(0x55, cipReplyOf(0x52, .success, a, &cb[0]), &fb[0])};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        var three: [3]u8 = undefined;
        try testing.expectError(error.BufferTooSmall, c.readTagFragmented("T", 1, &three));
        var four: [4]u8 = undefined;
        try testing.expectEqual(@as(usize, 4), (try c.readTagFragmented("T", 1, &four)).data.len);
    }
    // "More follows" with nothing in it must not loop.
    {
        const a = (types.TagData{ .type = .dint, .data = &.{} }).encode(&tdb) catch unreachable;
        const reps = [_][]const u8{rrCanned(0x55, cipReplyOf(0x52, .partial_transfer, a, &cb[0]), &fb[0])};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        try testing.expectError(error.MalformedReply, c.readTagFragmented("T", 1, &out));
    }
    // A structure's handle survives the reassembly.
    {
        const a = (types.TagData{ .type = .structure, .structure_handle = 0x1234, .data = &.{ 1, 2 } }).encode(&tdb) catch unreachable;
        const reps = [_][]const u8{rrCanned(0x55, cipReplyOf(0x52, .success, a, &cb[0]), &fb[0])};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        const r = try c.readTagFragmented("T", 1, &out);
        try testing.expectEqual(@as(?u16, 0x1234), r.structure_handle);
        try testing.expectEqual(DataType.structure, r.type);
    }
}

test "client: batching refuses what cannot be answered and counts what it was given" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var tap = Tap{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    var rq: [128]u8 = undefined;
    const r1 = try client.encodeReadTag("SCADA[0]", 1, &rq);
    var reps1: [1]cip.Reply = undefined;
    try testing.expectError(error.BufferTooSmall, c.multipleServices(&.{ r1, r1 }, &reps1));
    // The adapter refuses more than sixteen embedded requests; that outer failure is a CIP error.
    var many: [17][]const u8 = undefined;
    for (&many) |*m| m.* = r1;
    var reps17: [17]cip.Reply = undefined;
    try testing.expectError(error.CipError, c.multipleServices(&many, &reps17));
    // readTags: result slots, the eight-name ceiling, and a count of one per tag.
    const one_name = [_][]const u8{ "SCADA[0]", "SCADA[1]" };
    var one_slot: [1]?TagData = undefined;
    try testing.expectError(error.BufferTooSmall, c.readTags(&one_name, &one_slot));
    const eight: [8][]const u8 = @splat("SCADA[0]");
    var res8: [8]?TagData = undefined;
    try testing.expectEqual(@as(usize, 8), try c.readTags(&eight, &res8));
    try testing.expectEqual(@as(usize, 2), res8[0].?.data.len);
    const nine: [9][]const u8 = @splat("SCADA[0]");
    var res9: [9]?TagData = undefined;
    try testing.expectError(error.BufferTooSmall, c.readTags(&nine, &res9));
}

test "client: batched replies are bounded by the request count, and a partial outer reply is data" {
    var cb: [4][256]u8 = undefined;
    var fb: [4][512]u8 = undefined;
    var pb: [128]u8 = undefined;
    var buf: [2048]u8 = undefined;
    const emb = cipReplyOf(0x0E, .success, &.{}, &cb[0]);
    const req = [_]u8{ 0x0E, 2, 0x20, 1, 0x24, 1 };
    // Three embedded replies for two requests: two are returned.
    {
        const payload = cip.MultipleService.encode(&.{ emb, emb, emb }, &pb) catch unreachable;
        const reps = [_][]const u8{rrCanned(0x55, cipReplyOf(0x0A, .success, payload, &cb[1]), &fb[0])};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        var out: [2]cip.Reply = undefined;
        try testing.expectEqual(@as(usize, 2), try c.multipleServices(&.{ &req, &req }, &out));
    }
    // One embedded reply for two requests: one is returned, not an error for the missing second.
    {
        const payload = cip.MultipleService.encode(&.{emb}, &pb) catch unreachable;
        const reps = [_][]const u8{rrCanned(0x55, cipReplyOf(0x0A, .success, payload, &cb[1]), &fb[1])};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        var out: [2]cip.Reply = undefined;
        try testing.expectEqual(@as(usize, 1), try c.multipleServices(&.{ &req, &req }, &out));
    }
    // A partial_transfer outer status still carries a table.
    {
        const payload = cip.MultipleService.encode(&.{}, &pb) catch unreachable;
        const reps = [_][]const u8{rrCanned(0x55, cipReplyOf(0x0A, .partial_transfer, payload, &cb[1]), &fb[2])};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        var out: [1]cip.Reply = undefined;
        try testing.expectEqual(@as(usize, 0), try c.multipleServices(&.{}, out[0..0]));
    }
    // An embedded reply that failed is null even when it carries octets that would decode.
    {
        const bad = cipReplyOf(0x4C, .path_destination_unknown, &.{ 0xC3, 0, 1, 2 }, &cb[2]);
        const payload = cip.MultipleService.encode(&.{bad}, &pb) catch unreachable;
        const reps = [_][]const u8{rrCanned(0x55, cipReplyOf(0x0A, .success, payload, &cb[3]), &fb[3])};
        var tap = Tap{ .canned = &reps };
        var c = try cannedClient(&tap, &buf);
        var res: [1]?TagData = undefined;
        try testing.expectEqual(@as(usize, 1), try c.readTags(&.{"X"}, &res));
        try testing.expectEqual(@as(?TagData, null), res[0]);
    }
}

test "client: a read whose embedded reply is only partial still reports its type" {
    var l: [8]u8 = @splat(0);
    var tags = [_]TagBinding{.{ .name = "L", .type = .lint, .bytes = &l }};
    var target = Adapter.init(.{ .max_reply = 14 }, &tags);
    var tap = Tap{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    var res: [1]?TagData = undefined;
    try testing.expectEqual(@as(usize, 1), try c.readTags(&.{"L"}, &res));
    try testing.expectEqual(DataType.lint, res[0].?.type);
    try testing.expectEqual(@as(usize, 0), res[0].?.data.len);
}

test "forwardOpen sends the request it documents, and forwardClose closes by the same triple" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var tap = Tap{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{
        .originator_vendor_id = 0x4321,
        .originator_serial = 0x01020304,
        .cm_timeout = .{ .priority_time_tick = 0x0A, .timeout_ticks = 3 },
    });
    _ = try c.registerSession();
    try testing.expectError(error.NoConnection, c.forwardClose());
    const conn = try c.forwardOpen(.{ .size = 511, .rpi = 123456, .connection_serial = 0x1234 });
    try testing.expectEqual(@as(u32, 0x01000001), conn.o_to_t_id);
    try testing.expectEqual(@as(u32, 0x01000002), conn.t_to_o_id);
    try testing.expectEqual(@as(u16, 0x1234), conn.serial);
    try testing.expectEqual(@as(u16, 511), conn.size);
    var st: [8]cpf.Item = undefined;
    const req = try lastCip(&tap, &st);
    // The Forward_Open itself is sent to the Connection Manager, not wrapped in an Unconnected_Send.
    try testing.expectEqual(@as(u8, connmgr.Service.forward_open), req.service);
    const fo = try connmgr.ForwardOpen.decode(req.data, false);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x20, 0x02, 0x24, 0x01 }, fo.connection_path);
    try testing.expectEqual(@as(u32, 123456), fo.o_to_t_rpi);
    try testing.expectEqual(@as(u32, 123456), fo.t_to_o_rpi);
    try testing.expectEqual(@as(u16, 0x1234), fo.connection_serial);
    try testing.expectEqual(@as(u16, 0x4321), fo.originator_vendor_id);
    try testing.expectEqual(@as(u32, 0x01020304), fo.originator_serial);
    try testing.expectEqual(@as(u16, 511), fo.o_to_t_params.size);
    try testing.expect(fo.o_to_t_params.variable and fo.t_to_o_params.variable);
    try testing.expect(!fo.large);
    try testing.expectEqual(@as(u8, 0x0A), fo.timeout.priority_time_tick);
    try testing.expectEqual(@as(u8, 3), fo.timeout.timeout_ticks);

    // A connection past 511 octets needs the large form.
    const big = try c.forwardOpen(.{ .size = 512, .connection_serial = 5 });
    try testing.expectEqual(@as(u16, 512), big.size);
    const lreq = try lastCip(&tap, &st);
    try testing.expectEqual(@as(u8, connmgr.Service.large_forward_open), lreq.service);
    try testing.expect((try connmgr.ForwardOpen.decode(lreq.data, true)).large);

    // Close the second connection: the request carries the triple and the route.
    try c.forwardClose();
    const creq = try lastCip(&tap, &st);
    try testing.expectEqual(@as(u8, connmgr.Service.forward_close), creq.service);
    const fc = try connmgr.ForwardClose.decode(creq.data);
    try testing.expectEqual(@as(u16, 5), fc.connection_serial);
    try testing.expectEqual(@as(u16, 0x4321), fc.originator_vendor_id);
    try testing.expectEqual(@as(u32, 0x01020304), fc.originator_serial);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x20, 0x02, 0x24, 0x01 }, fc.connection_path);
    try testing.expectEqual(@as(?Connection, null), c.connection);

    // The pool holds four; the fifth open is refused with a CIP error.
    _ = try c.forwardOpen(.{ .connection_serial = 6 });
    _ = try c.forwardOpen(.{ .connection_serial = 7 });
    _ = try c.forwardOpen(.{ .connection_serial = 8 });
    try testing.expectError(error.CipError, c.forwardOpen(.{ .connection_serial = 9 }));
    // A close the target no longer recognises is a CIP error, and the client forgets the connection regardless.
    for (&target.connections) |*k| k.in_use = false;
    c.connection = .{ .o_to_t_id = 1, .t_to_o_id = 2, .serial = 77, .size = 500 };
    try testing.expectError(error.CipError, c.forwardClose());
    try testing.expectEqual(@as(?Connection, null), c.connection);
}

test "forwardOpen: the route, the connection path and their sizes" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var tap = Tap{ .target = &target };
    var buf: [8192]u8 = undefined;
    // A direct client has no route: the default path is just the Message Router.
    var d = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    _ = try d.registerSession();
    _ = try d.forwardOpen(.{});
    var st: [8]cpf.Item = undefined;
    const dreq = try lastCip(&tap, &st);
    const dfo = try connmgr.ForwardOpen.decode(dreq.data, false);
    try testing.expectEqualSlices(u8, &.{ 0x20, 0x02, 0x24, 0x01 }, dfo.connection_path);
    // An explicit path is appended to the route: 2 + 62 octets fit the 64-octet scratch, 2 + 64 do not.
    var r = try Client.init(tap.seam(), &buf, .{});
    r.registered = true;
    r.session_handle = d.session_handle;
    var p62: [62]u8 = undefined;
    for (&p62, 0..) |*b, i| b.* = @intCast(i);
    _ = try r.forwardOpen(.{ .connection_path = &p62 });
    const rreq = try lastCip(&tap, &st);
    const rfo = try connmgr.ForwardOpen.decode(rreq.data, false);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, rfo.connection_path[0..2]);
    try testing.expectEqualSlices(u8, &p62, rfo.connection_path[2..]);
    const p64: [64]u8 = @splat(0);
    try testing.expectError(error.BufferTooSmall, r.forwardOpen(.{ .connection_path = &p64 }));
}

test "a ListIdentity request carries the context it was given, and its reply is checked" {
    var out: [encap.header_len]u8 = undefined;
    const w = try client.encodeListIdentityRequest("ABCDEFGH".*, &out);
    try testing.expectEqualSlices(u8, "ABCDEFGH", w[12..20]);
    var fb: [128]u8 = undefined;
    const e1 = tapFrame(.list_services, 0, &.{ 0, 0 }, &fb);
    try testing.expectError(error.UnexpectedCommand, client.decodeListIdentityReply(e1));
    var raw: [64]u8 = undefined;
    const hdr = try encap.encode(.{ .command = .list_identity, .session_handle = 0, .status = .invalid_command, .sender_context = @splat(0), .options = 0, .data = &.{ 0, 0 }, .total_len = 0 }, &raw);
    try testing.expectError(error.EncapsulationError, client.decodeListIdentityReply(hdr));
}

// ── adapter: whole-module mutation audit 2026-11-17 ────────────────────────

fn cipGet(a: *Adapter, svc: u8, class: u32, inst: ?u32, attr: ?u32, out: []u8) ![]const u8 {
    var pb: [16]u8 = undefined;
    var b = epath.Builder.init(&pb);
    try b.class(class);
    if (inst) |i| try b.instance(i);
    if (attr) |x| try b.attribute(x);
    var rq: [32]u8 = undefined;
    const req = try (cip.Request{ .service = svc, .path = b.bytes(), .data = &.{} }).encode(&rq);
    return a.messageRouter(req, out);
}

fn unitFrame(session: u32, id: u32, seq: u16, cipreq: []const u8, out: []u8) []const u8 {
    var idle: [4]u8 = undefined;
    std.mem.writeInt(u32, &idle, id, .little);
    var cd: [128]u8 = undefined;
    const body = cpf.ConnectedData.encode(seq, cipreq, &cd) catch unreachable;
    const items = cpf.connectedItems(&idle, body);
    var env: [256]u8 = undefined;
    const e = cpf.encodeEnvelope(0, 0, &items, &env) catch unreachable;
    return tapFrame(.send_unit_data, session, e, out);
}

fn rrFrame(session: u32, cipreq: []const u8, out: []u8) []const u8 {
    const items = cpf.unconnectedItems(cipreq);
    var env: [512]u8 = undefined;
    const e = cpf.encodeEnvelope(0, 0, &items, &env) catch unreachable;
    return tapFrame(.send_rr_data, session, e, out);
}

fn foRequest(serial: u16, vendor: u16, orig: u32, o_rpi: u32, t_rpi: u32, out: []u8) []const u8 {
    return (connmgr.ForwardOpen{
        .o_to_t_connection_id = 0,
        .t_to_o_connection_id = 0,
        .connection_serial = serial,
        .originator_vendor_id = vendor,
        .originator_serial = orig,
        .o_to_t_rpi = o_rpi,
        .o_to_t_params = .{ .size = 100 },
        .t_to_o_rpi = t_rpi,
        .t_to_o_params = .{ .size = 100 },
        .connection_path = &.{ 0x20, 2, 0x24, 1 },
    }).wrap(out) catch unreachable;
}

fn fcRequest(serial: u16, vendor: u16, orig: u32, out: []u8) []const u8 {
    return (connmgr.ForwardClose{
        .connection_serial = serial,
        .originator_vendor_id = vendor,
        .originator_serial = orig,
        .connection_path = &.{ 0x20, 2, 0x24, 1 },
    }).wrap(out) catch unreachable;
}

fn expectAttr(a: *Adapter, attr: u32, want: []const u8) !void {
    var out: [128]u8 = undefined;
    const rep = try cip.Reply.decode(try cipGet(a, 0x0E, 1, 1, attr, &out));
    try testing.expectEqual(cip.GeneralStatus.success, rep.general_status);
    try testing.expectEqualSlices(u8, want, rep.data);
}

test "TagBinding: width, count, dimensions and the symbol type word" {
    var b8: [8]u8 = undefined;
    const arr = TagBinding{ .name = "A", .type = .dint, .bytes = &b8 };
    try testing.expectEqual(@as(usize, 4), arr.elementSize());
    try testing.expectEqual(@as(usize, 2), arr.elementCount());
    try testing.expectEqual(@as(u2, 1), arr.dimensionCount());
    try testing.expectEqual(@as(u16, 0x00C4 | (1 << 13)), arr.symbolType());
    const scalar = TagBinding{ .name = "A", .type = .dint, .bytes = b8[0..4] };
    try testing.expectEqual(@as(u2, 0), scalar.dimensionCount());
    try testing.expectEqual(@as(u16, 0x00C4), scalar.symbolType());
    const two = TagBinding{ .name = "T", .type = .int, .bytes = b8[0..4] };
    try testing.expectEqual(@as(u2, 1), two.dimensionCount());
    var b3: [3]u8 = undefined;
    const st = TagBinding{ .name = "S", .type = .structure, .bytes = &b3 };
    try testing.expectEqual(@as(usize, 1), st.elementSize());
    try testing.expectEqual(@as(usize, 3), st.elementCount());
    try testing.expectEqual(@as(u16, 0x00A0 | (1 << 13)), st.symbolType());
    try testing.expect(!st.isEnumerable());
}

test "adapter handle: output limits, statuses and session bookkeeping" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{ .revision_minor = 7 }, &tags);
    var rb: [256]u8 = undefined;
    var ob: [512]u8 = undefined;
    // Not even a header can be answered in ten octets, so a NOP is refused up front.
    try testing.expectError(error.BufferTooSmall, target.handle(tapFrame(.nop, 0, &.{}, &rb), ob[0..10]));
    // An unknown command is answered by a header alone, which fits 24 octets exactly.
    const unk = (try target.handle(tapFrame(.cancel, 0, &.{}, &rb), ob[0..24])).?;
    try testing.expectEqual(@as(usize, 24), unk.len);
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, unk[8..12], .little));
    // A protocol version other than 1 is refused and no session is opened.
    var rd: [4]u8 = undefined;
    const v2 = try (encap.RegisterSessionData{ .version = 2 }).encode(&rd);
    const refused = (try target.handle(tapFrame(.register_session, 0, v2, &rb), &ob)).?;
    try testing.expectEqual(@as(u32, 0x69), std.mem.readInt(u32, refused[8..12], .little));
    try testing.expectEqual(@as(usize, 24), refused.len);
    try testing.expectEqual(@as(u32, 0), target.session_handle);
    const garbage = (try target.handle(tapFrame(.register_session, 0, &.{1}, &rb), &ob)).?;
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, garbage[8..12], .little));
    const v1 = try (encap.RegisterSessionData{}).encode(&rd);
    const ok = (try target.handle(tapFrame(.register_session, 0, v1, &rb), &ob)).?;
    const h = std.mem.readInt(u32, ok[4..8], .little);
    try testing.expectEqual(@as(u32, 0xA5A5_0001), h);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, ok[8..12], .little));
    // A message in another session is refused; one in this session whose envelope is garbage is incorrect data.
    var q: [32]u8 = undefined;
    const get = try cip.getAttributeSingle(1, 1, 1, &q);
    const wrong = (try target.handle(rrFrame(h + 1, get, &rb), &ob)).?;
    try testing.expectEqual(@as(u32, 0x64), std.mem.readInt(u32, wrong[8..12], .little));
    const junk = (try target.handle(tapFrame(.send_rr_data, h, &.{ 1, 2, 3 }, &rb), &ob)).?;
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, junk[8..12], .little));
    const good = (try target.handle(rrFrame(h, get, &rb), &ob)).?;
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, good[8..12], .little));
    // ListIdentity reports the configured revision.
    const li = (try target.handle(tapFrame(.list_identity, 0, &.{}, &rb), &ob)).?;
    const msg = try encap.decode(li);
    var st: [4]cpf.Item = undefined;
    const list = try cpf.decode(msg.data, &st);
    try testing.expectEqual(@as(u8, 7), (try encap.Identity.decode(list.items[0].data)).revision_minor);
}

test "adapter identity object: every attribute, the class check and the name limit" {
    var target = Adapter.init(.{
        .vendor_id = 0x1111,
        .device_type = 0x0123,
        .product_code = 0x3333,
        .revision_major = 4,
        .revision_minor = 5,
        .identity_status = 0x4444,
        .serial_number = 0x55667788,
        .product_name = "abc",
        .state = .standby,
    }, &.{});
    try expectAttr(&target, 1, &.{ 0x11, 0x11 });
    try expectAttr(&target, 2, &.{ 0x23, 0x01 });
    try expectAttr(&target, 3, &.{ 0x33, 0x33 });
    try expectAttr(&target, 4, &.{ 4, 5 });
    try expectAttr(&target, 5, &.{ 0x44, 0x44 });
    try expectAttr(&target, 6, &.{ 0x88, 0x77, 0x66, 0x55 });
    try expectAttr(&target, 7, &.{ 3, 'a', 'b', 'c' });
    try expectAttr(&target, 8, &.{2});
    var out: [512]u8 = undefined;
    const all = try cip.Reply.decode(try cipGet(&target, 0x01, 1, 1, null, &out));
    try testing.expectEqualSlices(u8, &.{ 0x11, 0x11, 0x23, 0x01, 0x33, 0x33, 4, 5, 0x44, 0x44, 0x88, 0x77, 0x66, 0x55, 3, 'a', 'b', 'c' }, all.data);
    const unsupported = try cip.Reply.decode(try cipGet(&target, 0x0E, 1, 1, 9, &out));
    try testing.expectEqual(cip.GeneralStatus.attribute_not_supported, unsupported.general_status);
    const none = try cip.Reply.decode(try cipGet(&target, 0x0E, 1, 1, null, &out));
    try testing.expectEqual(cip.GeneralStatus.path_segment_error, none.general_status);
    // Another class is not the Identity object, for either service.
    for ([_]u8{ 0x01, 0x0E }) |svc| {
        const r = try cip.Reply.decode(try cipGet(&target, svc, 5, 1, 1, &out));
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, r.general_status);
    }
    // An unknown service is answered in its own reply code; a request that cannot be parsed in none.
    const unk = try cipGet(&target, 0x7F, 1, 1, null, &out);
    try testing.expectEqual(@as(u8, 0xFF), unk[0]);
    try testing.expectEqual(cip.GeneralStatus.service_not_supported, (try cip.Reply.decode(unk)).general_status);
    const mal = try cip.Reply.decode(try target.messageRouter(&.{0x0E}, &out));
    try testing.expectEqual(@as(u8, 0), mal.service);
    try testing.expectEqual(cip.GeneralStatus.message_format_error, mal.general_status);

    // A 200-character name fits, 201 does not — in either reply and through the encapsulation layer.
    const n200: [200]u8 = @splat('p');
    const n201: [201]u8 = @splat('p');
    var t200 = Adapter.init(.{ .product_name = &n200 }, &.{});
    try testing.expectEqual(@as(usize, 215), (try cip.Reply.decode(try cipGet(&t200, 0x01, 1, 1, null, &out))).data.len);
    try testing.expectEqual(@as(u8, 200), (try cip.Reply.decode(try cipGet(&t200, 0x0E, 1, 1, 7, &out))).data[0]);
    var t201 = Adapter.init(.{ .product_name = &n201 }, &.{});
    try testing.expectError(error.BufferTooSmall, cipGet(&t201, 0x01, 1, 1, null, &out));
    try testing.expectError(error.BufferTooSmall, cipGet(&t201, 0x0E, 1, 1, 7, &out));
    var rb: [256]u8 = undefined;
    var ob: [512]u8 = undefined;
    var rd: [4]u8 = undefined;
    const reg = (try t201.handle(tapFrame(.register_session, 0, try (encap.RegisterSessionData{}).encode(&rd), &rb), &ob)).?;
    const h = std.mem.readInt(u32, reg[4..8], .little);
    var q: [32]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, t201.handle(rrFrame(h, try cip.getAttributesAll(1, 1, &q), &rb), &ob));
}

test "adapter Program Name object: instance 1 only, a missing instance is not instance 1, the name limit" {
    const n256: [256]u8 = @splat('a');
    const n257: [257]u8 = @splat('a');
    var target = Adapter.init(.{ .program_name = &n256 }, &.{});
    var out: [600]u8 = undefined;
    const ok = try cip.Reply.decode(try cipGet(&target, 0x01, 0x64, 1, null, &out));
    try testing.expectEqual(@as(usize, 258), ok.data.len);
    try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, (try cip.Reply.decode(try cipGet(&target, 0x01, 0x64, null, null, &out))).general_status);
    try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, (try cip.Reply.decode(try cipGet(&target, 0x01, 0x64, 2, null, &out))).general_status);
    target.cfg.program_name = &n257;
    try testing.expectError(error.BufferTooSmall, cipGet(&target, 0x01, 0x64, 1, null, &out));
}

test "adapter Forward_Open: room is checked before a slot is taken; ids, intervals and the slot's fields" {
    var target = Adapter.init(.{}, &.{});
    var rq: [256]u8 = undefined;
    var out: [64]u8 = undefined;
    const req = foRequest(7, 0x1234, 0x55, 1000, 2000, &rq);
    try testing.expectError(error.BufferTooSmall, target.messageRouter(req, out[0..29]));
    try testing.expect(!target.connections[0].in_use);
    const ok = try target.messageRouter(req, out[0..30]);
    try testing.expectEqual(@as(usize, 30), ok.len);
    const fr = try connmgr.ForwardOpenReply.decode((try cip.Reply.decode(ok)).data);
    try testing.expectEqual(@as(u32, 0x01000001), fr.o_to_t_connection_id);
    try testing.expectEqual(@as(u32, 0x01000002), fr.t_to_o_connection_id);
    try testing.expectEqual(@as(u32, 1000), fr.o_to_t_api);
    try testing.expectEqual(@as(u32, 2000), fr.t_to_o_api);
    try testing.expectEqual(@as(u16, 7), fr.connection_serial);
    try testing.expectEqual(@as(u16, 0x1234), fr.originator_vendor_id);
    try testing.expectEqual(@as(u32, 0x55), fr.originator_serial);
    const slot = target.connections[0];
    try testing.expect(slot.in_use);
    try testing.expectEqual(@as(u32, 0x01000001), slot.o_to_t_id);
    try testing.expectEqual(@as(u32, 0x01000002), slot.t_to_o_id);
    try testing.expectEqual(@as(u16, 7), slot.serial);
    try testing.expectEqual(@as(u16, 0x1234), slot.vendor);
    try testing.expectEqual(@as(u32, 0x55), slot.originator_serial);
    const second = try connmgr.ForwardOpenReply.decode((try cip.Reply.decode(try target.messageRouter(foRequest(8, 1, 2, 3, 4, &rq), &out))).data);
    try testing.expectEqual(@as(u32, 0x01000003), second.o_to_t_connection_id);
    try testing.expectEqual(@as(u32, 0x01000004), second.t_to_o_connection_id);
}

test "adapter Forward_Close: room first, the whole triple must match, an empty slot is no match" {
    var target = Adapter.init(.{}, &.{});
    var rq: [256]u8 = undefined;
    var out: [64]u8 = undefined;
    const nf = try target.messageRouter(fcRequest(0, 0, 0, &rq), &out);
    const nfr = try cip.Reply.decode(nf);
    try testing.expectEqual(cip.GeneralStatus.connection_failure, nfr.general_status);
    try testing.expectEqualSlices(u8, &.{ 0x07, 0x01 }, nfr.additional_status);
    try testing.expectEqual(@as(u8, 0xCE), nf[0]);
    _ = try target.messageRouter(foRequest(7, 0x1234, 0x55, 1, 2, &rq), &out);
    const wrong = [_][3]u32{ .{ 8, 0x1234, 0x55 }, .{ 7, 0x9999, 0x55 }, .{ 7, 0x1234, 0x56 } };
    for (wrong) |t| {
        const r = try cip.Reply.decode(try target.messageRouter(fcRequest(@intCast(t[0]), @intCast(t[1]), t[2], &rq), &out));
        try testing.expectEqual(cip.GeneralStatus.connection_failure, r.general_status);
        try testing.expect(target.connections[0].in_use);
    }
    try testing.expectError(error.BufferTooSmall, target.messageRouter(fcRequest(7, 0x1234, 0x55, &rq), out[0..13]));
    try testing.expect(target.connections[0].in_use);
    const done = try target.messageRouter(fcRequest(7, 0x1234, 0x55, &rq), out[0..14]);
    try testing.expectEqual(@as(usize, 14), done.len);
    try testing.expect(!target.connections[0].in_use);
    const again = try cip.Reply.decode(try target.messageRouter(fcRequest(7, 0x1234, 0x55, &rq), &out));
    try testing.expectEqual(cip.GeneralStatus.connection_failure, again.general_status);
}

test "adapter unit data: only an open connection answers, and ending the session closes them all" {
    var target = Adapter.init(.{}, &.{});
    var rb: [512]u8 = undefined;
    var ob: [512]u8 = undefined;
    var rd: [4]u8 = undefined;
    const reg = (try target.handle(tapFrame(.register_session, 0, try (encap.RegisterSessionData{}).encode(&rd), &rb), &ob)).?;
    const h = std.mem.readInt(u32, reg[4..8], .little);
    var rq: [256]u8 = undefined;
    var out: [64]u8 = undefined;
    _ = try target.messageRouter(foRequest(7, 0x1234, 0x55, 1, 2, &rq), &out);
    var q: [32]u8 = undefined;
    const get = try cip.getAttributeSingle(1, 1, 1, &q);
    const ok = (try target.handle(unitFrame(h, 0x01000001, 9, get, &rb), &ob)).?;
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, ok[8..12], .little));
    var st: [8]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope((try encap.decode(ok)).data, &st);
    try testing.expectEqual(@as(u16, 9), (try cpf.ConnectedData.decode(env.list.dataItem().?)).sequence_count);
    const unknown = (try target.handle(unitFrame(h, 0x12345, 9, get, &rb), &ob)).?;
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, unknown[8..12], .little));
    _ = try target.messageRouter(fcRequest(7, 0x1234, 0x55, &rq), &out);
    const closed = (try target.handle(unitFrame(h, 0x01000001, 10, get, &rb), &ob)).?;
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, closed[8..12], .little));
    _ = try target.messageRouter(foRequest(7, 0x1234, 0x55, 1, 2, &rq), &out);
    try testing.expect(target.connections[0].in_use);
    try testing.expectEqual(@as(?[]const u8, null), try target.handle(tapFrame(.unregister_session, h, &.{}, &rb), &ob));
    try testing.expect(!target.connections[0].in_use);
    try testing.expectEqual(@as(u32, 0), target.session_handle);
}

test "adapter: nesting is bounded for Unconnected_Send and for Multiple_Service_Packet" {
    var target = Adapter.init(.{}, &.{});
    var out: [4096]u8 = undefined;
    var wb: [6][1200]u8 = undefined;
    var inner: [32]u8 = undefined;
    var cur: []const u8 = try cip.getAttributeSingle(1, 1, 1, &inner);
    for (1..5) |k| cur = try (connmgr.UnconnectedSend{ .embedded = cur, .route_path = &connmgr.backplane_slot_0 }).wrap(&wb[k]);
    const four = try cip.Reply.decode(try target.messageRouter(cur, &out));
    try testing.expectEqual(cip.GeneralStatus.success, four.general_status);
    try testing.expectEqual(@as(u8, 0x0E), four.service);
    cur = try (connmgr.UnconnectedSend{ .embedded = cur, .route_path = &connmgr.backplane_slot_0 }).wrap(&wb[5]);
    const five = try cip.Reply.decode(try target.messageRouter(cur, &out));
    try testing.expectEqual(cip.GeneralStatus.resource_unavailable, five.general_status);
    try testing.expectEqual(@as(u8, 0), five.service);

    var rq: [32]u8 = undefined;
    const unknown = try (cip.Request{ .service = 0x7F, .path = &.{ 0x20, 2, 0x24, 1 }, .data = &.{} }).encode(&rq);
    var bufs: [6][512]u8 = undefined;
    var pbs: [6][512]u8 = undefined;
    var c2: []const u8 = unknown;
    for (0..6) |k| c2 = try encodeBatch(&[_][]const u8{c2}, &pbs[k], &bufs[k]);
    var rep = try cip.Reply.decode(try target.messageRouter(c2, &out));
    for (0..5) |_| {
        try testing.expectEqual(cip.GeneralStatus.success, rep.general_status);
        const ms = try cip.MultipleService.decode(rep.data);
        rep = try cip.Reply.decode(try ms.at(0));
    }
    try testing.expectEqual(cip.GeneralStatus.resource_unavailable, rep.general_status);
}

test "adapter Multiple_Service_Packet: the reply budget is exact at its edges" {
    var target = Adapter.init(.{}, &.{});
    var rq: [32]u8 = undefined;
    const u = try (cip.Request{ .service = 0x7F, .path = &.{ 0x20, 2, 0x24, 1 }, .data = &.{} }).encode(&rq);
    var pb: [64]u8 = undefined;
    var bb: [128]u8 = undefined;
    const msp = try encodeBatch(&[_][]const u8{ u, u }, &pb, &bb);
    var out: [64]u8 = undefined;
    const ok = try target.messageRouter(msp, out[0..18]);
    try testing.expectEqual(@as(usize, 18), ok.len);
    const okr = try cip.Reply.decode(ok);
    try testing.expectEqual(cip.GeneralStatus.success, okr.general_status);
    const ms = try cip.MultipleService.decode(okr.data);
    try testing.expectEqual(@as(usize, 2), ms.count);
    for (0..2) |i| {
        const e = try cip.Reply.decode(try ms.at(i));
        try testing.expectEqual(@as(u8, 0x7F), e.service);
        try testing.expectEqual(cip.GeneralStatus.service_not_supported, e.general_status);
    }
    const no = try cip.Reply.decode(try target.messageRouter(msp, out[0..17]));
    try testing.expectEqual(cip.GeneralStatus.reply_data_too_large, no.general_status);

    var many: [17][]const u8 = @splat(u);
    var pb2: [512]u8 = undefined;
    var bb2: [512]u8 = undefined;
    var big: [1024]u8 = undefined;
    const m17 = try encodeBatch(&many, &pb2, &bb2);
    try testing.expectEqual(cip.GeneralStatus.too_much_data, (try cip.Reply.decode(try target.messageRouter(m17, &big))).general_status);
    const m16 = try encodeBatch(many[0..16], &pb2, &bb2);
    try testing.expectEqual(cip.GeneralStatus.success, (try cip.Reply.decode(try target.messageRouter(m16, &big))).general_status);

    // An embedded reply that cannot fit its share is answered as too large, in its own service code.
    var t2 = Adapter.init(.{ .max_reply = 40 }, &.{});
    var q2: [32]u8 = undefined;
    const ga = try cip.getAttributesAll(1, 1, &q2);
    const msp2 = try encodeBatch(&[_][]const u8{ ga, u }, &pb, &bb);
    var out4: [4096]u8 = undefined;
    const r2 = try cip.Reply.decode(try t2.messageRouter(msp2, &out4));
    try testing.expectEqual(cip.GeneralStatus.success, r2.general_status);
    const ms2 = try cip.MultipleService.decode(r2.data);
    try testing.expectEqualSlices(u8, &.{ 0x81, 0, 0x11, 0 }, try ms2.at(0));
}

fn symReq(start: ?u32, attrs: []const u16, out: []u8) []const u8 {
    var pb: [16]u8 = undefined;
    var b = epath.Builder.init(&pb);
    b.class(0x6B) catch unreachable;
    if (start) |s| b.instance(s) catch unreachable;
    var db: [64]u8 = undefined;
    std.mem.writeInt(u16, db[0..2], @intCast(attrs.len), .little);
    for (attrs, 0..) |a, i| std.mem.writeInt(u16, db[2 + i * 2 ..][0..2], a, .little);
    return (cip.Request{ .service = 0x55, .path = b.bytes(), .data = db[0 .. 2 + attrs.len * 2] }).encode(out) catch unreachable;
}

test "symbol list: a record that exactly fills the room is delivered" {
    var ib: [2]u8 = undefined;
    const tags = [_]TagBinding{.{ .name = "A", .type = .int, .bytes = &ib }};
    const Case = struct { attrs: []const u16, len: usize };
    const cases = [_]Case{
        .{ .attrs = &.{}, .len = 4 },
        .{ .attrs = &.{1}, .len = 7 },
        .{ .attrs = &.{2}, .len = 6 },
        .{ .attrs = &.{3}, .len = 8 },
        .{ .attrs = &.{5}, .len = 8 },
        .{ .attrs = &.{6}, .len = 8 },
        .{ .attrs = &.{8}, .len = 16 },
        .{ .attrs = &.{10}, .len = 5 },
    };
    for (cases) |cs| {
        var target = Adapter.init(.{ .max_reply = 8 + cs.len }, &tags);
        var rq: [64]u8 = undefined;
        var out: [128]u8 = undefined;
        const rep = try cip.Reply.decode(try target.messageRouter(symReq(null, cs.attrs, &rq), &out));
        try testing.expectEqual(cip.GeneralStatus.success, rep.general_status);
        try testing.expectEqual(cs.len, rep.data.len);
    }
}

test "symbol list: request validation, unsupported attributes and the caller's buffer" {
    var ia: [2]u8 = undefined;
    var ib: [2]u8 = undefined;
    var ic: [2]u8 = undefined;
    const tags = [_]TagBinding{
        .{ .name = "A", .type = .int, .bytes = &ia },
        .{ .name = "B", .type = .int, .bytes = &ib },
        .{ .name = "C", .type = .int, .bytes = &ic },
    };
    var target = Adapter.init(.{}, &tags);
    var rq: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const bad7 = try cip.Reply.decode(try target.messageRouter(symReq(null, &.{7}, &rq), &out));
    try testing.expectEqual(cip.GeneralStatus.attribute_not_supported, bad7.general_status);
    var pb: [16]u8 = undefined;
    var b = epath.Builder.init(&pb);
    try b.class(0x6B);
    const raw = [_]struct { data: []const u8, want: cip.GeneralStatus }{
        .{ .data = &.{1}, .want = .not_enough_data },
        .{ .data = &.{ 0, 0 }, .want = .success },
        .{ .data = &.{ 3, 0, 1, 0, 2, 0 }, .want = .not_enough_data },
    };
    for (raw) |r| {
        const req = try (cip.Request{ .service = 0x55, .path = b.bytes(), .data = r.data }).encode(&rq);
        try testing.expectEqual(r.want, (try cip.Reply.decode(try target.messageRouter(req, &out))).general_status);
    }
    // A 20-octet buffer leaves room for one 7-octet record, not two: the rest is a continuation.
    const part = try cip.Reply.decode(try target.messageRouter(symReq(null, &.{1}, &rq), out[0..20]));
    try testing.expectEqual(cip.GeneralStatus.partial_transfer, part.general_status);
    try testing.expectEqual(@as(usize, 7), part.data.len);
    // The same list with room to spare is complete.
    const full = try cip.Reply.decode(try target.messageRouter(symReq(null, &.{1}, &rq), &out));
    try testing.expectEqual(cip.GeneralStatus.success, full.general_status);
    try testing.expectEqual(@as(usize, 21), full.data.len);
}

test "adapter tag lookup: names are exact; instance ids need the Symbol class and an enumerable tag" {
    var s3: [3]u8 = @splat(1);
    var iv: [4]u8 = @splat(2);
    const tags = [_]TagBinding{
        .{ .name = "S", .type = .structure, .bytes = &s3 },
        .{ .name = "SCADA", .type = .int, .bytes = &iv },
    };
    var target = Adapter.init(.{}, &tags);
    var rq: [128]u8 = undefined;
    var out: [128]u8 = undefined;
    const lower = try client.encodeReadTag("scada[0]", 1, &rq);
    try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, (try cip.Reply.decode(try target.messageRouter(lower, &out))).general_status);
    const exact = try client.encodeReadTag("SCADA[0]", 1, &rq);
    try testing.expectEqual(cip.GeneralStatus.success, (try cip.Reply.decode(try target.messageRouter(exact, &out))).general_status);
    const byname = try client.encodeReadTag("S", 1, &rq);
    try testing.expectEqual(cip.GeneralStatus.success, (try cip.Reply.decode(try target.messageRouter(byname, &out))).general_status);
    const Case = struct { class: u32, inst: u32, want: cip.GeneralStatus };
    const cases = [_]Case{
        .{ .class = 0x6B, .inst = 2, .want = .success },
        .{ .class = 0x6B, .inst = 1, .want = .path_destination_unknown },
        .{ .class = 0x6B, .inst = 0, .want = .path_destination_unknown },
        .{ .class = 0x6B, .inst = 3, .want = .path_destination_unknown },
        .{ .class = 0x02, .inst = 2, .want = .path_destination_unknown },
    };
    for (cases) |cs| {
        var pb: [16]u8 = undefined;
        var b = epath.Builder.init(&pb);
        try b.class(cs.class);
        try b.instance(cs.inst);
        const req = try (cip.Request{ .service = cip.LogixService.read_tag, .path = b.bytes(), .data = &.{ 1, 0 } }).encode(&rq);
        try testing.expectEqual(cs.want, (try cip.Reply.decode(try target.messageRouter(req, &out))).general_status);
    }
}

fn fragReadReq(name: []const u8, count: u16, offset: u32, out: []u8) []const u8 {
    var pb: [64]u8 = undefined;
    const path = tagpath.encodePath(name, &pb) catch unreachable;
    var db: [6]u8 = undefined;
    const data = (types.ReadTagFragmentedRequest{ .count = count, .byte_offset = offset }).encode(&db) catch unreachable;
    return (cip.Request{ .service = cip.LogixService.read_tag_fragmented, .path = path, .data = data }).encode(out) catch unreachable;
}

fn writeReq(name: []const u8, t: DataType, count: u16, values: []const u8, out: []u8) []const u8 {
    var pb: [64]u8 = undefined;
    const path = tagpath.encodePath(name, &pb) catch unreachable;
    var db: [256]u8 = undefined;
    const data = (types.WriteTagRequest{ .type = t, .count = count, .values = values }).encode(&db) catch unreachable;
    return (cip.Request{ .service = cip.LogixService.write_tag, .path = path, .data = data }).encode(out) catch unreachable;
}

test "adapter tag reads: offsets, counts, room and request validation" {
    var d40: [40]u8 = @splat(7);
    var sb: [100]u8 = @splat(1);
    const tags = [_]TagBinding{
        .{ .name = "D", .type = .dint, .bytes = &d40 },
        .{ .name = "S", .type = .sint, .bytes = &sb },
    };
    var target = Adapter.init(.{}, &tags);
    var rq: [128]u8 = undefined;
    var out: [256]u8 = undefined;
    // An offset equal to the tag's length is an empty read; one past it is out of range.
    const at_end = try cip.Reply.decode(try target.messageRouter(fragReadReq("D", 1, 40, &rq), &out));
    try testing.expectEqual(cip.GeneralStatus.success, at_end.general_status);
    try testing.expectEqual(@as(usize, 0), (try types.TagData.decode(at_end.data)).data.len);
    const past = try cip.Reply.decode(try target.messageRouter(fragReadReq("D", 1, 41, &rq), &out));
    try testing.expectEqual(cip.GeneralStatus.invalid_parameter_value, past.general_status);
    // A read larger than the caller's buffer is cut to it, with a partial_transfer.
    const cut = try cip.Reply.decode(try target.messageRouter(try client.encodeReadTag("S", 100, &rq), out[0..60]));
    try testing.expectEqual(cip.GeneralStatus.partial_transfer, cut.general_status);
    try testing.expectEqual(@as(usize, 52), (try types.TagData.decode(cut.data)).data.len);
    // Requests with a short body.
    var pb: [64]u8 = undefined;
    const path = try tagpath.encodePath("D", &pb);
    const short_plain = try (cip.Request{ .service = cip.LogixService.read_tag, .path = path, .data = &.{} }).encode(&rq);
    try testing.expectEqual(cip.GeneralStatus.not_enough_data, (try cip.Reply.decode(try target.messageRouter(short_plain, &out))).general_status);
    const short_frag = try (cip.Request{ .service = cip.LogixService.read_tag_fragmented, .path = path, .data = &.{ 1, 0 } }).encode(&rq);
    try testing.expectEqual(cip.GeneralStatus.not_enough_data, (try cip.Reply.decode(try target.messageRouter(short_frag, &out))).general_status);
    const short_write = try (cip.Request{ .service = cip.LogixService.write_tag, .path = path, .data = &.{ 1, 0 } }).encode(&rq);
    try testing.expectEqual(cip.GeneralStatus.not_enough_data, (try cip.Reply.decode(try target.messageRouter(short_write, &out))).general_status);
}

test "adapter tag writes: type, range, room and what is left untouched" {
    var w: [200]u8 = @splat(0);
    const tags = [_]TagBinding{.{ .name = "W", .type = .int, .bytes = &w }};
    var target = Adapter.init(.{}, &tags);
    var rq: [512]u8 = undefined;
    var out: [64]u8 = undefined;
    const wrong = try cip.Reply.decode(try target.messageRouter(writeReq("W[0]", .dint, 1, &.{ 1, 0, 0, 0 }, &rq), &out));
    try testing.expectEqual(cip.GeneralStatus.invalid_attribute_value, wrong.general_status);
    // Element 99 is the last INT: two octets fit, four do not.
    const over = try cip.Reply.decode(try target.messageRouter(writeReq("W[99]", .int, 2, &.{ 1, 0, 2, 0 }, &rq), &out));
    try testing.expectEqual(cip.GeneralStatus.too_much_data, over.general_status);
    const last = try cip.Reply.decode(try target.messageRouter(writeReq("W[99]", .int, 1, &.{ 9, 0 }, &rq), &out));
    try testing.expectEqual(cip.GeneralStatus.success, last.general_status);
    try testing.expectEqual(@as(u8, 9), w[198]);
    // An empty write exactly at the end is still a write of nothing, not an error.
    const empty = try cip.Reply.decode(try target.messageRouter(writeReq("W[100]", .int, 0, &.{}, &rq), &out));
    try testing.expectEqual(cip.GeneralStatus.success, empty.general_status);
    // Without room to answer, nothing changes.
    try testing.expectError(error.BufferTooSmall, target.messageRouter(writeReq("W[0]", .int, 1, &.{ 5, 0 }, &rq), out[0..3]));
    try testing.expectEqual(@as(u8, 0), w[0]);
    _ = try target.messageRouter(writeReq("W[0]", .int, 1, &.{ 5, 0 }, &rq), out[0..4]);
    try testing.expectEqual(@as(u8, 5), w[0]);
}

test "adapter Reset: refused with its own status, accepted into exactly four octets" {
    var out: [16]u8 = undefined;
    var refuse = Adapter.init(.{}, &.{});
    const r = try cipGet(&refuse, 0x05, 1, 1, null, &out);
    try testing.expectEqual(@as(u8, 0x85), r[0]);
    try testing.expectEqual(cip.GeneralStatus.privilege_violation, (try cip.Reply.decode(r)).general_status);
    var allow = Adapter.init(.{ .allow_reset = true }, &.{});
    try testing.expectError(error.BufferTooSmall, cipGet(&allow, 0x05, 1, 1, null, out[0..3]));
    try testing.expect(!allow.reset_requested);
    const done = try cipGet(&allow, 0x05, 1, 1, null, out[0..4]);
    try testing.expectEqual(@as(usize, 4), done.len);
    try testing.expect(allow.reset_requested);
}

test "a connected request that overflows the envelope does not consume a sequence count" {
    var scada: [64]u8 = @splat(0);
    var dint: [8]u8 = @splat(0);
    var real: [8]u8 = @splat(0);
    var tags = testTags(&scada, &dint, &real);
    var target = Adapter.init(.{}, &tags);
    var tap = Tap{ .target = &target };
    var buf: [2048]u8 = undefined;
    var c = try Client.init(tap.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    _ = try c.forwardOpen(.{});
    // 300 octets pass the 64-octet margin guard but cannot be framed in the 512-octet half.
    const big: [300]u8 = @splat(0);
    try testing.expectError(error.BufferTooSmall, c.sendConnectedCip(&big));
    try testing.expectEqual(@as(u16, 0), c.connection.?.sequence);
    var q: [32]u8 = undefined;
    _ = try c.sendConnectedCip(try cip.getAttributeSingle(1, 1, 1, &q));
    try testing.expectEqual(@as(u16, 1), c.connection.?.sequence);
}

// ── TCP/IP Interface object (class 0xF5) ────────────────────────────────────

const tcpip_cfg: adapter.Config = .{
    .tcpip = .{
        .status = 1,
        .configuration_capability = 0x04,
        .configuration_control = 0x02,
        .ip_address = .{ 192, 168, 1, 10 },
        .network_mask = .{ 255, 255, 255, 0 },
        .gateway = .{ 192, 168, 1, 1 },
        .name_server = .{ 8, 8, 8, 8 },
        .domain_name = "lan",
        .host_name = "plc01",
    },
};

/// One request through the Message Router; the reply is copied into `keep`.
fn routed(target: *Adapter, req: []const u8, keep: []u8) !cip.Reply {
    var out: [512]u8 = undefined;
    const raw = try target.messageRouter(req, &out);
    @memcpy(keep[0..raw.len], raw);
    return cip.Reply.decode(keep[0..raw.len]);
}

test "tcpip object: Get_Attributes_All and every attribute, request octets to reply octets" {
    var target = Adapter.init(tcpip_cfg, &.{});
    var keep: [512]u8 = undefined;
    var rb: [64]u8 = undefined;
    const class = @backingInt(ClassCode.tcp_ip_interface);

    // 03 ... `01 02 20 F5 24 01` is Get_Attributes_All on 0xF5 / 1.
    const all_req = try cip.getAttributesAll(class, 1, &rb);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x20, 0xF5, 0x24, 0x01 }, all_req);
    const all = try routed(&target, all_req, &keep);
    try testing.expectEqual(cip.GeneralStatus.success, all.general_status);
    try testing.expectEqual(@as(u8, 0x01), all.service);
    const expect_all = [_]u8{
        1, 0, 0, 0, // status
        4, 0, 0, 0, // capability
        2, 0, 0, 0, // control
        2, 0, 0x20, 0xF6, 0x24, 1, // physical link: 2 words, class F6, instance 1
        10, 1, 0xA8, 0xC0, // 192.168.1.10
        0, 255, 255, 255, // 255.255.255.0
        1, 1, 0xA8, 0xC0, // 192.168.1.1
        8, 8, 8, 8, // name server
        0, 0, 0, 0, // name server 2
        3, 0, 'l', 'a', 'n', 0, // domain name, padded
        5, 0, 'p', 'l', 'c', '0', '1', 0, // host name, padded
    };
    try testing.expectEqualSlices(u8, &expect_all, all.data);

    // The same octets, attribute by attribute, in order.
    var off: usize = 0;
    const widths = [_]usize{ 4, 4, 4, 6, 26, 8 };
    for (widths, 1..) |w, a| {
        const r = try routed(&target, try cip.getAttributeSingle(class, 1, @intCast(a), &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.success, r.general_status);
        try testing.expectEqual(@as(u8, 0x0E), r.service);
        try testing.expectEqualSlices(u8, expect_all[off..][0..w], r.data);
        off += w;
    }
    try testing.expectEqual(expect_all.len, off);
    // None of this counts as an identity request.
    try testing.expectEqual(@as(usize, 0), target.identity_requests);
}

test "tcpip object: refusals" {
    var target = Adapter.init(tcpip_cfg, &.{});
    var keep: [512]u8 = undefined;
    var rb: [64]u8 = undefined;
    const class = @backingInt(ClassCode.tcp_ip_interface);

    // Unknown attributes: 0x14, including 0x14 itself and one past 16 bits.
    for ([_]u32{ 0x14, 7, 0, 13, 0x10001, 0x1_0000 }) |a| {
        const r = try routed(&target, try cip.getAttributeSingle(class, 1, a, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.attribute_not_supported, r.general_status);
        try testing.expectEqual(@as(usize, 0), r.data.len);
        try testing.expectEqual(@as(u8, 0x0E), r.service);
    }
    // Unknown instances, for each service.
    for ([_]u32{ 0, 2, 255 }) |inst| {
        const g = try routed(&target, try cip.getAttributeSingle(class, inst, 1, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, g.general_status);
        const ga = try routed(&target, try cip.getAttributesAll(class, inst, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, ga.general_status);
        const s = try routed(&target, try cip.setAttributeSingle(class, inst, 6, &.{ 1, 0, 'a', 0 }, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, s.general_status);
    }
    // A path with no instance at all (`20 F5 30 06`).
    var pb: [8]u8 = undefined;
    var b = epath.Builder.init(&pb);
    try b.class(class);
    try b.attribute(6);
    var rq: [32]u8 = undefined;
    for ([_]u8{ 0x01, 0x0E, 0x10 }) |svc| {
        const noinst = try (cip.Request{ .service = svc, .path = b.bytes(), .data = &.{ 1, 0, 'a', 0 } }).encode(&rq);
        const r = try routed(&target, noinst, &keep);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, r.general_status);
        try testing.expectEqual(svc, r.service);
    }
    // Get_Attribute_Single and Set_Attribute_Single without an attribute segment.
    var pb2: [8]u8 = undefined;
    var b2 = epath.Builder.init(&pb2);
    try b2.class(class);
    try b2.instance(1);
    for ([_]u8{ 0x0E, 0x10 }) |svc| {
        const q = try (cip.Request{ .service = svc, .path = b2.bytes(), .data = &.{ 0, 0, 0, 0 } }).encode(&rq);
        const r = try routed(&target, q, &keep);
        try testing.expectEqual(cip.GeneralStatus.path_segment_error, r.general_status);
        try testing.expectEqual(svc, r.service);
    }
    // Services the object does not have: Create (0x08), Delete, Set_Attributes_All.
    for ([_]u8{ 0x08, 0x09, 0x02, 0x03 }) |svc| {
        const q = try (cip.Request{ .service = svc, .path = b2.bytes(), .data = &.{} }).encode(&rq);
        const r = try routed(&target, q, &keep);
        try testing.expectEqual(cip.GeneralStatus.service_not_supported, r.general_status);
        try testing.expectEqual(svc, r.service);
    }
    // Set is refused by default: not settable, for every attribute it has,
    // and the value is untouched afterwards.
    for ([_]u32{ 1, 2, 3, 4, 5, 6 }) |a| {
        const r = try routed(&target, try cip.setAttributeSingle(class, 1, a, &.{ 1, 0, 'a', 0 }, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.attribute_not_settable, r.general_status);
        try testing.expectEqual(@as(u8, 0x10), r.service);
    }
    for ([_]u32{ 7, 0x14, 0x1_0006 }) |a| {
        const r = try routed(&target, try cip.setAttributeSingle(class, 1, a, &.{ 1, 0, 'a', 0 }, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.attribute_not_supported, r.general_status);
    }
    const host = try routed(&target, try cip.getAttributeSingle(class, 1, 6, &rb), &keep);
    try testing.expectEqualSlices(u8, &.{ 5, 0, 'p', 'l', 'c', '0', '1', 0 }, host.data);
    // Set_Attribute_Single stays unclaimed on every other class.
    const id = try routed(&target, try cip.setAttributeSingle(@backingInt(ClassCode.identity), 1, 7, &.{ 0, 0 }, &rb), &keep);
    try testing.expectEqual(cip.GeneralStatus.service_not_supported, id.general_status);
    // Withheld: the class answers as before it existed.
    var without = Adapter.init(.{ .tcpip = null }, &.{});
    for ([_]u8{ 0x01, 0x0E, 0x10 }) |svc| {
        const q = try (cip.Request{ .service = svc, .path = (try epath.logicalPath(class, 1, 1, &pb)), .data = &.{} }).encode(&rq);
        const r = try routed(&without, q, &keep);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, r.general_status);
    }
}

test "tcpip object: round trip through the client with Set enabled" {
    var cfg = tcpip_cfg;
    cfg.allow_tcpip_set = true;
    var target = Adapter.init(cfg, &.{});
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    const class = @backingInt(ClassCode.tcp_ip_interface);

    // Settable advertises itself in the capability word.
    const caps = try c.getAttributeSingle(class, 1, 2);
    try testing.expectEqualSlices(u8, &.{ 0x14, 0, 0, 0 }, caps);

    // DHCP is configured, so an address is refused until the method is static.
    var data: [64]u8 = undefined;
    const words = [5]u32{ 0x0A000007, 0xFFFF0000, 0x0A000001, 0, 0 };
    for (words, 0..) |w, i| std.mem.writeInt(u32, data[i * 4 ..][0..4], w, .little);
    std.mem.writeInt(u16, data[20..22], 0, .little);
    try testing.expectError(error.CipError, c.setAttributeSingle(class, 1, 5, data[0..22]));
    try c.setAttributeSingle(class, 1, 3, &.{ 0, 0, 0, 0 });
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, try c.getAttributeSingle(class, 1, 3));
    try c.setAttributeSingle(class, 1, 5, data[0..22]);
    try testing.expectEqualSlices(u8, data[0..22], try c.getAttributeSingle(class, 1, 5));
    try c.setAttributeSingle(class, 1, 6, &.{ 3, 0, 'p', 'l', 'c', 0 });
    try testing.expectEqualSlices(u8, &.{ 3, 0, 'p', 'l', 'c', 0 }, try c.getAttributeSingle(class, 1, 6));
    // A non-empty domain name is stored too (odd length, with its pad octet).
    std.mem.writeInt(u16, data[20..22], 3, .little);
    @memcpy(data[22..25], "lan");
    data[25] = 0;
    try c.setAttributeSingle(class, 1, 5, data[0..26]);
    try testing.expectEqualSlices(u8, data[0..26], try c.getAttributeSingle(class, 1, 5));
    std.mem.writeInt(u16, data[20..22], 0, .little);
    try c.setAttributeSingle(class, 1, 5, data[0..22]);
    // The pending bit shows in the status, and Get_Attributes_All sees all of it.
    try testing.expectEqualSlices(u8, &.{ 0x11, 0, 0, 0 }, try c.getAttributeSingle(class, 1, 1));
    const all = try c.getAttributesAll(class, 1);
    try testing.expectEqual(@as(usize, 12 + 6 + 22 + 6), all.len);
    try testing.expectEqualSlices(u8, data[0..22], all[18..40]);
    // A bad value is refused and changes nothing.
    try testing.expectError(error.CipError, c.setAttributeSingle(class, 1, 6, &.{ 1, 0, '-', 0 }));
    try testing.expectEqualSlices(u8, &.{ 3, 0, 'p', 'l', 'c', 0 }, try c.getAttributeSingle(class, 1, 6));
    // The status attribute stays read-only even with Set enabled.
    try testing.expectError(error.CipError, c.setAttributeSingle(class, 1, 1, &.{ 0, 0, 0, 0 }));
}

// ── Ethernet Link object (class 0xF6) ───────────────────────────────────────

test "ethernet link object: Get_Attributes_All and every attribute, request octets to reply octets" {
    var target = Adapter.init(.{ .ethernet_link = .{
        .interface_speed = 1000,
        .interface_flags = 0x0F,
        .physical_address = .{ 0x00, 0x1D, 0x9C, 0xAA, 0xBB, 0xCC },
    } }, &.{});
    var keep: [512]u8 = undefined;
    var rb: [64]u8 = undefined;
    const class = @backingInt(ClassCode.ethernet_link);

    const all_req = try cip.getAttributesAll(class, 1, &rb);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x20, 0xF6, 0x24, 0x01 }, all_req);
    const all = try routed(&target, all_req, &keep);
    try testing.expectEqual(cip.GeneralStatus.success, all.general_status);
    try testing.expectEqual(@as(u8, 0x01), all.service);
    const expect_all = [_]u8{ 0xE8, 3, 0, 0, 0x0F, 0, 0, 0, 0x00, 0x1D, 0x9C, 0xAA, 0xBB, 0xCC };
    try testing.expectEqualSlices(u8, &expect_all, all.data);

    var off: usize = 0;
    for ([_]usize{ 4, 4, 6 }, 1..) |w, a| {
        const r = try routed(&target, try cip.getAttributeSingle(class, 1, @intCast(a), &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.success, r.general_status);
        try testing.expectEqual(@as(u8, 0x0E), r.service);
        try testing.expectEqualSlices(u8, expect_all[off..][0..w], r.data);
        off += w;
    }
    try testing.expectEqual(expect_all.len, off);
    try testing.expectEqual(@as(usize, 0), target.identity_requests);

    // The defaults are served when nothing is configured.
    var dflt = Adapter.init(.{}, &.{});
    const d = try routed(&dflt, try cip.getAttributesAll(class, 1, &rb), &keep);
    try testing.expectEqualSlices(u8, &.{ 100, 0, 0, 0, 0x0F, 0, 0, 0, 0x02, 0, 0, 0, 0, 1 }, d.data);
}

test "ethernet link object: refusals" {
    var target = Adapter.init(.{}, &.{});
    var keep: [512]u8 = undefined;
    var rb: [64]u8 = undefined;
    const class = @backingInt(ClassCode.ethernet_link);

    // Optional attributes (counters 4 and 5, interface control 6, ...) and
    // anything else are not supported.
    for ([_]u32{ 0x14, 4, 5, 6, 10, 0, 0x10001, 0x1_0000 }) |a| {
        const r = try routed(&target, try cip.getAttributeSingle(class, 1, a, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.attribute_not_supported, r.general_status);
        try testing.expectEqual(@as(usize, 0), r.data.len);
        try testing.expectEqual(@as(u8, 0x0E), r.service);
    }
    for ([_]u32{ 0, 2, 255 }) |inst| {
        const g = try routed(&target, try cip.getAttributeSingle(class, inst, 1, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, g.general_status);
        const ga = try routed(&target, try cip.getAttributesAll(class, inst, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, ga.general_status);
    }
    var pb: [8]u8 = undefined;
    var b = epath.Builder.init(&pb);
    try b.class(class);
    try b.attribute(1);
    var rq: [32]u8 = undefined;
    for ([_]u8{ 0x01, 0x0E }) |svc| {
        const noinst = try (cip.Request{ .service = svc, .path = b.bytes(), .data = &.{} }).encode(&rq);
        const r = try routed(&target, noinst, &keep);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, r.general_status);
        try testing.expectEqual(svc, r.service);
    }
    var pb2: [8]u8 = undefined;
    var b2 = epath.Builder.init(&pb2);
    try b2.class(class);
    try b2.instance(1);
    const noattr = try (cip.Request{ .service = 0x0E, .path = b2.bytes(), .data = &.{} }).encode(&rq);
    const na = try routed(&target, noattr, &keep);
    try testing.expectEqual(cip.GeneralStatus.path_segment_error, na.general_status);
    // Services the object does not have: Create (0x08), Delete, Set_Attribute_Single
    // (the object is read-only here), Set_Attributes_All.
    for ([_]u8{ 0x08, 0x09, 0x10, 0x02, 0x03 }) |svc| {
        const q = try (cip.Request{ .service = svc, .path = b2.bytes(), .data = &.{ 0, 0, 0, 0 } }).encode(&rq);
        const r = try routed(&target, q, &keep);
        try testing.expectEqual(cip.GeneralStatus.service_not_supported, r.general_status);
        try testing.expectEqual(svc, r.service);
    }
    // Withheld.
    var without = Adapter.init(.{ .ethernet_link = null }, &.{});
    for ([_]u8{ 0x01, 0x0E }) |svc| {
        const q = try (cip.Request{ .service = svc, .path = (try epath.logicalPath(class, 1, 1, &pb)), .data = &.{} }).encode(&rq);
        const r = try routed(&without, q, &keep);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, r.general_status);
    }
}

test "ethernet link object: the client reads it, next to the TCP/IP object that points at it" {
    var target = Adapter.init(.{ .ethernet_link = .{ .interface_speed = 10, .interface_flags = 0x0E } }, &.{});
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    const link = @backingInt(ClassCode.ethernet_link);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 0 }, try c.getAttributeSingle(link, 1, 1));
    try testing.expectEqualSlices(u8, &.{ 0x0E, 0, 0, 0 }, try c.getAttributeSingle(link, 1, 2));
    try testing.expectEqual(@as(usize, 6), (try c.getAttributeSingle(link, 1, 3)).len);
    try testing.expectEqual(@as(usize, 14), (try c.getAttributesAll(link, 1)).len);
    try testing.expectError(error.CipError, c.getAttributeSingle(link, 1, 4));
    try testing.expectError(error.CipError, c.setAttributeSingle(link, 1, 1, &.{ 0, 0, 0, 0 }));
    // The physical link path the TCP/IP object reports names this very object.
    const path = try c.getAttributeSingle(@backingInt(ClassCode.tcp_ip_interface), 1, 4);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 0x20, 0xF6, 0x24, 1 }, path);
}

// ── Assembly object (class 0x04) ────────────────────────────────────────────

const AsmHooks = struct {
    gets: usize = 0,
    sets: usize = 0,
    accept: bool = true,
    last: [8]u8 = @splat(0),

    fn before(ctx: ?*anyopaque, data: []u8) void {
        const self: *AsmHooks = @ptrCast(@alignCast(ctx.?));
        self.gets += 1;
        data[0] = @intCast(self.gets); // the application refreshes its input
    }

    fn after(ctx: ?*anyopaque, data: []const u8) bool {
        const self: *AsmHooks = @ptrCast(@alignCast(ctx.?));
        self.sets += 1;
        @memcpy(self.last[0..data.len], data);
        return self.accept;
    }
};

var asm_list_storage: [4]stdobj.Assembly = undefined;

/// Instances 100 (read-only input, 4 octets), 150 (writable output, 3 octets,
/// hooks), 7 (writable, empty) and a repeat of 100 that must be ignored.
fn asmTarget(in: []u8, outp: []u8, hooks: *AsmHooks, empty: []u8, shadow: []u8) Adapter {
    asm_list_storage = .{
        .{ .instance = 100, .data = in },
        .{ .instance = 150, .data = outp, .writable = true, .ctx = hooks, .before_get = AsmHooks.before, .after_set = AsmHooks.after },
        .{ .instance = 7, .data = empty, .writable = true },
        .{ .instance = 100, .data = shadow },
    };
    return Adapter.init(.{ .assemblies = &asm_list_storage }, &.{});
}

test "assembly object: octets both ways, class attributes and sizes" {
    var in = [4]u8{ 1, 2, 3, 4 };
    var outp = [3]u8{ 9, 9, 9 };
    var empty: [0]u8 = .{};
    var shadow = [4]u8{ 0xEE, 0xEE, 0xEE, 0xEE };
    var hooks: AsmHooks = .{};
    var target = asmTarget(&in, &outp, &hooks, &empty, &shadow);
    var keep: [512]u8 = undefined;
    var rb: [64]u8 = undefined;
    const class = @backingInt(ClassCode.assembly);

    // Get_Attribute_Single data of 0x04 / 100 / 3, on the wire.
    const get3 = try cip.getAttributeSingle(class, 100, 3, &rb);
    try testing.expectEqualSlices(u8, &.{ 0x0E, 0x03, 0x20, 0x04, 0x24, 0x64, 0x30, 0x03 }, get3);
    var out: [64]u8 = undefined;
    const raw = try target.messageRouter(get3, &out);
    try testing.expectEqualSlices(u8, &.{ 0x8E, 0x00, 0x00, 0x00, 1, 2, 3, 4 }, raw);

    // Size, as a UINT; the repeated instance id is answered from its first entry.
    const s = try routed(&target, try cip.getAttributeSingle(class, 100, 4, &rb), &keep);
    try testing.expectEqualSlices(u8, &.{ 4, 0 }, s.data);
    const s2 = try routed(&target, try cip.getAttributeSingle(class, 150, 4, &rb), &keep);
    try testing.expectEqualSlices(u8, &.{ 3, 0 }, s2.data);
    const s0 = try routed(&target, try cip.getAttributeSingle(class, 7, 4, &rb), &keep);
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, s0.data);
    const d0 = try routed(&target, try cip.getAttributeSingle(class, 7, 3, &rb), &keep);
    try testing.expectEqual(cip.GeneralStatus.success, d0.general_status);
    try testing.expectEqual(@as(usize, 0), d0.data.len);

    // Class attributes: revision 2, max instance 150, 3 instances, 7, 4.
    const want = [_]struct { a: u32, v: u16 }{ .{ .a = 1, .v = 2 }, .{ .a = 2, .v = 150 }, .{ .a = 3, .v = 3 }, .{ .a = 6, .v = 7 }, .{ .a = 7, .v = 4 } };
    for (want) |w| {
        const r = try routed(&target, try cip.getAttributeSingle(class, 0, w.a, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.success, r.general_status);
        var exp: [2]u8 = undefined;
        std.mem.writeInt(u16, &exp, w.v, .little);
        try testing.expectEqualSlices(u8, &exp, r.data);
    }
    try testing.expectEqual(@as(usize, 0), hooks.gets);

    // The read hook refreshes the buffer first (instance 150 byte 0 = call count).
    const r150 = try routed(&target, try cip.getAttributeSingle(class, 150, 3, &rb), &keep);
    try testing.expectEqualSlices(u8, &.{ 1, 9, 9 }, r150.data);
    try testing.expectEqual(@as(usize, 1), hooks.gets);
    // The size read does not touch the hook.
    _ = try routed(&target, try cip.getAttributeSingle(class, 150, 4, &rb), &keep);
    try testing.expectEqual(@as(usize, 1), hooks.gets);

    // Set 0x04 / 150 / 3 on the wire; the stored octets and the hook agree.
    const set3 = try cip.setAttributeSingle(class, 150, 3, &.{ 0xA1, 0xB2, 0xC3 }, &rb);
    try testing.expectEqualSlices(u8, &.{ 0x10, 0x03, 0x20, 0x04, 0x24, 0x96, 0x30, 0x03, 0xA1, 0xB2, 0xC3 }, set3);
    const raw2 = try target.messageRouter(set3, &out);
    try testing.expectEqualSlices(u8, &.{ 0x90, 0x00, 0x00, 0x00 }, raw2);
    try testing.expectEqualSlices(u8, &.{ 0xA1, 0xB2, 0xC3 }, &outp);
    try testing.expectEqual(@as(usize, 1), hooks.sets);
    try testing.expectEqualSlices(u8, &.{ 0xA1, 0xB2, 0xC3 }, hooks.last[0..3]);
    // The empty instance takes an empty Set.
    const sete = try routed(&target, try cip.setAttributeSingle(class, 7, 3, &.{}, &rb), &keep);
    try testing.expectEqual(cip.GeneralStatus.success, sete.general_status);
    // The application's own writes come back through the buffer.
    in[0] = 0x55;
    const again = try routed(&target, try cip.getAttributeSingle(class, 100, 3, &rb), &keep);
    try testing.expectEqualSlices(u8, &.{ 0x55, 2, 3, 4 }, again.data);
    // None of it is an identity request.
    try testing.expectEqual(@as(usize, 0), target.identity_requests);
}

test "assembly object: every refusal" {
    var in = [4]u8{ 1, 2, 3, 4 };
    var outp = [3]u8{ 9, 9, 9 };
    var empty: [0]u8 = .{};
    var shadow = [4]u8{ 0xEE, 0xEE, 0xEE, 0xEE };
    var hooks: AsmHooks = .{};
    var target = asmTarget(&in, &outp, &hooks, &empty, &shadow);
    var keep: [512]u8 = undefined;
    var rb: [64]u8 = undefined;
    var pb: [16]u8 = undefined;
    var rq: [64]u8 = undefined;
    const class = @backingInt(ClassCode.assembly);
    const S = cip.GeneralStatus;

    // Unknown instances (0x05), for Get and Set, including ids above 16 bits.
    for ([_]u32{ 1, 99, 101, 255, 0x10064 }) |inst| {
        const g = try routed(&target, try cip.getAttributeSingle(class, inst, 3, &rb), &keep);
        try testing.expectEqual(S.path_destination_unknown, g.general_status);
        try testing.expectEqual(@as(u8, 0x0E), g.service);
        const t = try routed(&target, try cip.setAttributeSingle(class, inst, 3, &.{1}, &rb), &keep);
        try testing.expectEqual(S.path_destination_unknown, t.general_status);
        try testing.expectEqual(@as(u8, 0x10), t.service);
    }
    // Unknown attributes (0x14): 0, 1, 2, 5, 0x14, and ones past 16 bits.
    for ([_]u32{ 0, 1, 2, 5, 0x14, 0x10003, 0x10004 }) |a| {
        const g = try routed(&target, try cip.getAttributeSingle(class, 150, a, &rb), &keep);
        try testing.expectEqual(S.attribute_not_supported, g.general_status);
        const t = try routed(&target, try cip.setAttributeSingle(class, 150, a, &.{ 1, 2, 3 }, &rb), &keep);
        try testing.expectEqual(S.attribute_not_supported, t.general_status);
    }
    // Class attributes not served: 0, 4 and 5 (optional lists), 8, 0x14.
    for ([_]u32{ 0, 4, 5, 8, 0x14, 0x10001 }) |a| {
        const g = try routed(&target, try cip.getAttributeSingle(class, 0, a, &rb), &keep);
        try testing.expectEqual(S.attribute_not_supported, g.general_status);
        try testing.expectEqual(@as(usize, 0), g.data.len);
    }
    // Set on the read-only instance (right size and wrong size alike), on the
    // size attribute, and on the class.
    const ro = try routed(&target, try cip.setAttributeSingle(class, 100, 3, &.{ 1, 2, 3, 4 }, &rb), &keep);
    try testing.expectEqual(S.attribute_not_settable, ro.general_status);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, &in);
    const ro_len = try routed(&target, try cip.setAttributeSingle(class, 100, 3, &.{9}, &rb), &keep);
    try testing.expectEqual(S.attribute_not_settable, ro_len.general_status);
    const sz = try routed(&target, try cip.setAttributeSingle(class, 150, 4, &.{ 3, 0 }, &rb), &keep);
    try testing.expectEqual(S.attribute_not_settable, sz.general_status);
    const ro_size = try routed(&target, try cip.setAttributeSingle(class, 100, 4, &.{ 4, 0 }, &rb), &keep);
    try testing.expectEqual(S.attribute_not_settable, ro_size.general_status);
    for ([_]u32{ 1, 2, 3, 6, 7 }) |a| {
        const c = try routed(&target, try cip.setAttributeSingle(class, 0, a, &.{ 1, 0 }, &rb), &keep);
        try testing.expectEqual(S.service_not_supported, c.general_status);
        try testing.expectEqual(@as(u8, 0x10), c.service);
    }
    // Wrong sizes on the writable one: 0x13 short, 0x15 long; nothing stored, no hook.
    for ([_][]const u8{ &.{}, &.{1}, &.{ 1, 2 } }) |v| {
        const r = try routed(&target, try cip.setAttributeSingle(class, 150, 3, v, &rb), &keep);
        try testing.expectEqual(S.not_enough_data, r.general_status);
    }
    for ([_][]const u8{ &.{ 1, 2, 3, 4 }, &.{ 1, 2, 3, 4, 5, 6 } }) |v| {
        const r = try routed(&target, try cip.setAttributeSingle(class, 150, 3, v, &rb), &keep);
        try testing.expectEqual(S.too_much_data, r.general_status);
    }
    const long0 = try routed(&target, try cip.setAttributeSingle(class, 7, 3, &.{0}, &rb), &keep);
    try testing.expectEqual(S.too_much_data, long0.general_status);
    try testing.expectEqualSlices(u8, &.{ 9, 9, 9 }, &outp);
    try testing.expectEqual(@as(usize, 0), hooks.sets);
    // The application's hook can refuse: invalid_attribute_value, octets already stored (OpENer).
    hooks.accept = false;
    const bad = try routed(&target, try cip.setAttributeSingle(class, 150, 3, &.{ 4, 5, 6 }, &rb), &keep);
    try testing.expectEqual(S.invalid_attribute_value, bad.general_status);
    try testing.expectEqualSlices(u8, &.{ 4, 5, 6 }, &outp);
    try testing.expectEqual(@as(usize, 1), hooks.sets);
    // Get_Attributes_All is a service this class does not have, on the class and on instances.
    for ([_]u32{ 0, 100, 150, 9 }) |inst| {
        const r = try routed(&target, try cip.getAttributesAll(class, inst, &rb), &keep);
        try testing.expectEqual(S.service_not_supported, r.general_status);
        try testing.expectEqual(@as(u8, 0x01), r.service);
    }
    // A missing attribute segment is a path segment error.
    for ([_]u8{ 0x0E, 0x10 }) |svc| {
        const q = try (cip.Request{ .service = svc, .path = (try epath.logicalPath(class, 100, null, &pb)), .data = &.{} }).encode(&rq);
        try testing.expectEqual(S.path_segment_error, (try routed(&target, q, &keep)).general_status);
    }
    // A path with no instance segment addresses the class: its attribute is
    // served, and Set is the service the class does not have.
    const no_inst = [_]u8{ 0x20, 0x04, 0x30, 0x01 };
    const cg = try (cip.Request{ .service = 0x0E, .path = &no_inst, .data = &.{} }).encode(&rq);
    const cgr = try routed(&target, cg, &keep);
    try testing.expectEqual(S.success, cgr.general_status);
    try testing.expectEqualSlices(u8, &.{ 2, 0 }, cgr.data);
    const cs = try (cip.Request{ .service = 0x10, .path = &no_inst, .data = &.{ 2, 0 } }).encode(&rq);
    try testing.expectEqual(S.service_not_supported, (try routed(&target, cs, &keep)).general_status);
    // Other services stay unsupported, as for every other class.
    for ([_]u8{ 0x02, 0x03, 0x08, 0x09, 0x0B }) |svc| {
        const q = try (cip.Request{ .service = svc, .path = (try epath.logicalPath(class, 100, 3, &pb)), .data = &.{} }).encode(&rq);
        const r = try routed(&target, q, &keep);
        try testing.expectEqual(S.service_not_supported, r.general_status);
    }
}

test "assembly object: withheld without instances, and a buffer too big for the size attribute is not served" {
    var target = Adapter.init(.{}, &.{});
    var keep: [512]u8 = undefined;
    var rb: [64]u8 = undefined;
    const class = @backingInt(ClassCode.assembly);
    for ([_]u8{ 0x01, 0x0E }) |svc| {
        var pb: [16]u8 = undefined;
        var rq: [64]u8 = undefined;
        const q = try (cip.Request{ .service = svc, .path = (try epath.logicalPath(class, 1, 3, &pb)), .data = &.{} }).encode(&rq);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, (try routed(&target, q, &keep)).general_status);
    }
    // The class itself is withheld too, not just its instances.
    for ([_]u32{ 1, 2, 3 }) |a| {
        const c = try routed(&target, try cip.getAttributeSingle(class, 0, a, &rb), &keep);
        try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, c.general_status);
    }
    // Set stays "service not supported" when the class is not served.
    const s = try routed(&target, try cip.setAttributeSingle(class, 1, 3, &.{1}, &rb), &keep);
    try testing.expectEqual(cip.GeneralStatus.service_not_supported, s.general_status);

    const big = try testing.allocator.alloc(u8, 65536);
    defer testing.allocator.free(big);
    @memset(big, 0);
    var ok: [2]u8 = .{ 5, 6 };
    const list = [_]stdobj.Assembly{
        .{ .instance = 1, .data = big },
        .{ .instance = 2, .data = &ok },
    };
    var t2 = Adapter.init(.{ .assemblies = &list }, &.{});
    const g1 = try routed(&t2, try cip.getAttributeSingle(class, 1, 4, &rb), &keep);
    try testing.expectEqual(cip.GeneralStatus.path_destination_unknown, g1.general_status);
    const c3 = try routed(&t2, try cip.getAttributeSingle(class, 0, 3, &rb), &keep);
    try testing.expectEqualSlices(u8, &.{ 1, 0 }, c3.data);
    const c2 = try routed(&t2, try cip.getAttributeSingle(class, 0, 2, &rb), &keep);
    try testing.expectEqualSlices(u8, &.{ 2, 0 }, c2.data);
    // The largest legal one (65535 octets) is served; its size is 0xFFFF.
    const edge_list = [_]stdobj.Assembly{.{ .instance = 9, .data = big[0..65535] }};
    var edge = Adapter.init(.{ .assemblies = &edge_list }, &.{});
    var wide: [128]u8 = undefined;
    const raw = try edge.messageRouter(try cip.getAttributeSingle(class, 9, 4, &rb), &wide);
    try testing.expectEqualSlices(u8, &.{ 0x8E, 0, 0, 0, 0xFF, 0xFF }, raw);
}

test "assembly object: the client and the adapter, round trip" {
    var in = [4]u8{ 1, 2, 3, 4 };
    var outp = [3]u8{ 0, 0, 0 };
    var empty: [0]u8 = .{};
    var shadow: [1]u8 = .{0};
    var hooks: AsmHooks = .{};
    var target = asmTarget(&in, &outp, &hooks, &empty, &shadow);
    var paired = PairedTransport{ .target = &target };
    var buf: [8192]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{ .routing = .direct });
    _ = try c.registerSession();
    const class = @backingInt(ClassCode.assembly);

    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, try c.getAttributeSingle(class, 100, 3));
    try testing.expectEqualSlices(u8, &.{ 4, 0 }, try c.getAttributeSingle(class, 100, 4));
    try c.setAttributeSingle(class, 150, 3, &.{ 7, 8, 9 });
    try testing.expectEqualSlices(u8, &.{ 7, 8, 9 }, &outp);
    // Read back through the wire (byte 0 is refreshed by the read hook).
    try testing.expectEqualSlices(u8, &.{ 1, 8, 9 }, try c.getAttributeSingle(class, 150, 3));
    try testing.expectError(error.CipError, c.setAttributeSingle(class, 100, 3, &.{ 0, 0, 0, 0 }));
    try testing.expectError(error.CipError, c.setAttributeSingle(class, 150, 3, &.{ 0, 0 }));
    try testing.expectError(error.CipError, c.getAttributeSingle(class, 151, 3));
    try testing.expectError(error.CipError, c.getAttributesAll(class, 100));
    try testing.expectEqualSlices(u8, &.{ 3, 0 }, try c.getAttributeSingle(class, 0, 3));
}

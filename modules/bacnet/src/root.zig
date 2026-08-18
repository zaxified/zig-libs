// SPDX-License-Identifier: MIT

//! bacnet — pure-Zig **BACnet (ASHRAE 135)** over both of its IP-family data
//! links: the building-automation protocol that HVAC, lighting, access control
//! and fire panels speak to a building-management system.
//!
//! Wire layers, each usable on its own, plus the roles on top of them:
//!
//! * **`bvll`** (Annex J) — the BACnet/IP virtual link layer: `81 | function |
//!   length` in front of every datagram, with the length checked against what
//!   the socket actually delivered. Original unicast/broadcast NPDUs,
//!   `Forwarded-NPDU`, and the BBMD/foreign-device functions that exist
//!   because IP broadcasts do not cross subnets.
//! * **`npdu`** (clause 6) — the network layer, whose layout the **control
//!   octet decides**: which of DNET/DLEN/DADR, SNET/SLEN/SADR and the hop
//!   count are present. A decoder that assumes a fixed prefix reads the APDU
//!   from the wrong offset, which is the classic BACnet bug. Plus the
//!   network-layer routing messages.
//! * **`apdu`** (clause 20.1) — the eight PDU types, including **segmentation**
//!   parsed properly: the SEG bit moves the service choice by two octets, and
//!   a segmented PDU is returned as a typed segment rather than silently
//!   flattened into a wrong decode.
//! * **`tag`** (clause 20.2) — **the heart of BACnet**: application versus
//!   context tags, the tag-number escape, the length/value/type field with its
//!   5/254/65535 escapes, the Boolean-in-LVT special case, opening/closing
//!   brackets, and every primitive type — CharacterString with its encoding
//!   octet, BitString with its unused-bits count, ObjectIdentifier packing a
//!   10-bit type and a 22-bit instance into one word.
//! * **`service`** (clauses 15/16) — ReadProperty, ReadPropertyMultiple with
//!   its `ALL`/`REQUIRED`/`OPTIONAL` wildcards and per-property errors,
//!   WriteProperty with the priority array and the NULL relinquish,
//!   Who-Is/I-Am, Who-Has/I-Have, SubscribeCOV and both notification forms,
//!   and ReadRange.
//! * **`client` / `device`** — a client (discover, read, write, subscribe) and
//!   a device (an object database that answers all of it), both over one
//!   datagram seam, both **pure and time-injected**: no clock, no thread, no
//!   socket inside.
//! * **`sc`** (Annex AB) — **BACnet/SC**, which replaces the datagram link
//!   with a mesh of WebSockets over TLS: a different BVLC with a message id,
//!   6-octet **VMAC** addressing, a 16-octet device UUID, and two
//!   self-terminating header-option lists whose *must-understand* bit decides
//!   whether an unknown option is fatal. There is no length field — the
//!   WebSocket frame is the boundary.
//! * **`sc_node` / `sc_hub` / `sc_ws`** — a BACnet/SC node (connect,
//!   negotiate, heartbeat, jittered reconnect, primary/failover hub, VMAC
//!   collision recovery), the hub that makes it testable (admission, UUID and
//!   VMAC collision handling, attribution, distribution), and the WebSocket
//!   binding over the sibling `websocket` module — with **TLS as an explicit
//!   seam** the caller fills in, never faked here.
//!
//! Verified against **byte-exact goldens from independent implementations** and
//! by **live round trips in both directions** on both data links; see
//! `goldens.zig`, `sc_goldens.zig`, `interop.zig`, `sc_interop.zig` and
//! SPEC.md for exactly what came from where — including which BACnet/SC peer
//! was and was not obtainable, and a byte-order disagreement between two
//! third-party stacks that Wireshark's dissector settled.
//!
//! Provenance: clean-room from ASHRAE 135's documented encodings. Third-party
//! stacks were used as black-box oracles and live peers; one function of one
//! of them was read while probing its API. See SPEC.md and `/NOTICE`.

const std = @import("std");

pub const meta = .{
    // Every codec, the client and the device are pure computation; only the
    // optional UdpTransport touches std.Io.net.
    .targets = .{.linux64},
    .platform = .any,
    .role = .both, // client + device (responder)
    // One Client/Device owns its transaction table, subscriptions and
    // buffers; nothing shared or global. Concurrency and the clock belong to
    // the caller.
    .concurrency = .single_owner,
    .model_after = "ASHRAE 135 (BACnet) Annex J + Annex AB + clauses 6, 15, 16, 20; wire behaviour byte-compared against bacpypes3, bacnet-stack and Wireshark's dissector, and validated by live round trips in both directions on both data links (see SPEC.md)",
    .deps = .{ "netaddr", "websocket" },
};

// ── layers ──────────────────────────────────────────────────────────────────

/// Object types, property identifiers, service choices, error/reject/abort
/// reasons and the common enumerations.
pub const types = @import("types.zig");
/// Clause 20.2 tag encoding — the heart of BACnet.
pub const tag = @import("tag.zig");
/// Annex J BACnet/IP virtual link layer.
pub const bvll = @import("bvll.zig");
/// Clause 6 network layer.
pub const npdu = @import("npdu.zig");
/// Clause 20.1 application layer PDUs.
pub const apdu = @import("apdu.zig");
/// Clause 15/16 services.
pub const service = @import("service.zig");
/// The datagram seam and its adapters.
pub const transport = @import("transport.zig");
/// A BACnet/IP client.
pub const client = @import("client.zig");
/// A BACnet/IP device (responder).
pub const device = @import("device.zig");
/// Annex AB BACnet/SC virtual link layer (BVLC-SC) — the WebSocket-and-TLS
/// data link, with its VMAC addressing and header options.
pub const sc = @import("sc.zig");
/// The BACnet/SC WebSocket binding and the TLS seam.
pub const sc_ws = @import("sc_ws.zig");
/// A BACnet/SC node: the connection state machine, pure and time-injected.
pub const sc_node = @import("sc_node.zig");
/// A BACnet/SC hub: admission, VMAC resolution and distribution.
pub const sc_hub = @import("sc_hub.zig");
/// Byte-exact goldens from an independent implementation.
pub const goldens = @import("goldens.zig");
/// Byte-exact BACnet/SC goldens from two independent implementations.
pub const sc_goldens = @import("sc_goldens.zig");
/// Live interop tests, gated on an environment variable.
pub const interop = @import("interop.zig");
/// Live BACnet/SC interop over a real WebSocket, gated on an environment
/// variable.
pub const sc_interop = @import("sc_interop.zig");

// ── top-level names (the ones a consumer actually types) ────────────────────

/// A BACnet/IP client with room for 16 concurrent confirmed transactions.
pub const Client = client.DefaultClient;
/// A BACnet/IP device with room for 16 COV subscriptions.
pub const Device = device.DefaultDevice;
/// A client sized for a chosen number of concurrent transactions.
pub const ClientWith = client.Client;
/// A device sized for a chosen number of COV subscriptions.
pub const DeviceWith = device.Device;

/// The datagram seam: `send`, `broadcast`, `recv`.
pub const Transport = transport.Transport;
pub const TransportError = transport.TransportError;
/// Optional adapter onto a real UDP socket.
pub const UdpTransport = transport.UdpTransport;
/// In-memory network, for offline round trips.
pub const LoopNetwork = transport.LoopNetwork;
pub const LoopTransport = transport.LoopTransport;

/// A BACnet/SC node (Annex AB): one WebSocket to a hub, time-injected.
pub const ScNode = sc_node.Node;
pub const ScNodeWith = sc_node.NodeWith;
/// A BACnet/SC hub (Annex AB): admission, VMAC resolution and distribution.
pub const ScHub = sc_hub.Hub;
pub const ScHubWith = sc_hub.HubWith;
/// A BACnet/SC virtual MAC address and device UUID.
pub const Vmac = sc.Vmac;
pub const Uuid = sc.Uuid;

/// A BACnet/IP address: four octets of IPv4 plus a UDP port.
pub const BipAddress = bvll.BipAddress;
/// The registered BACnet/IP UDP port, 47808 (`0xBAC0`).
pub const default_port = bvll.default_port;

/// An object identifier: a 10-bit type and a 22-bit instance in one word.
pub const ObjectId = tag.ObjectId;
pub const ObjectType = types.ObjectType;
pub const PropertyIdentifier = types.PropertyIdentifier;
pub const ErrorClass = types.ErrorClass;
pub const ErrorCode = types.ErrorCode;
pub const Segmentation = types.Segmentation;
pub const StatusFlags = types.StatusFlags;

/// A decoded application-tagged datum.
pub const Value = tag.Value;
pub const CharacterString = tag.CharacterString;
pub const BitString = tag.BitString;
pub const Date = tag.Date;
pub const Time = tag.Time;

/// One object in a `Device`'s database.
pub const Object = device.Object;
/// One property of one object.
pub const Property = device.Property;
/// A property value a `Device` can store and serve.
pub const PropertyValue = device.Value;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ───────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s tests
// into the test binary on its own — every submodule must be named here too.
test {
    _ = types;
    _ = tag;
    _ = bvll;
    _ = npdu;
    _ = apdu;
    _ = service;
    _ = transport;
    _ = client;
    _ = device;
    _ = sc;
    _ = sc_ws;
    _ = sc_node;
    _ = sc_hub;
    _ = goldens;
    _ = sc_goldens;
    _ = interop;
    _ = sc_interop;
}

// ── tests: the stack end to end ────────────────────────────────────────────

const testing = std.testing;

test "meta names its sibling dependencies" {
    try testing.expectEqual(@as(usize, 2), meta.deps.len);
    try testing.expectEqualStrings("netaddr", meta.deps[0]);
    // BACnet/SC rides on RFC 6455; the framing is the `websocket` module's,
    // not a second copy living here.
    try testing.expectEqualStrings("websocket", meta.deps[1]);
}

test "a whole datagram, built and torn down through every layer" {
    // The point of this test is that the layers compose without a helper: a
    // caller can build a BACnet/IP datagram from the bottom up and read one
    // back the same way.
    var vbuf: [8]u8 = undefined;
    var vw = tag.Writer.init(&vbuf);
    try vw.appReal(72.5);

    var sbuf: [64]u8 = undefined;
    var sw = tag.Writer.init(&sbuf);
    try (service.ReadPropertyAck{
        .object = .{ .type = .analog_input, .instance = 5 },
        .property = .present_value,
        .value = vw.written(),
    }).encode(&sw);

    var abuf: [96]u8 = undefined;
    const a = try apdu.encode(.{ .complex_ack = .{
        .invoke_id = 1,
        .service = .read_property,
        .data = sw.written(),
    } }, &abuf);

    var nbuf: [128]u8 = undefined;
    const n = try npdu.encode(.{}, a, &nbuf);

    var dbuf: [160]u8 = undefined;
    const dgram = try bvll.wrap(.original_unicast_npdu, n, &dbuf);

    // This is the exact datagram bacpypes3 produced for the same ACK.
    var expect: [64]u8 = undefined;
    const want = try std.fmt.hexToBytes(
        &expect,
        "810a0017010030010c0c0000000519553e44429100003f",
    );
    try testing.expectEqualSlices(u8, want, dgram);

    // ... and back down again.
    const b = try bvll.decode(dgram);
    const back_n = try npdu.decode(b.npdu().?);
    const back_a = try apdu.decode(back_n.payload.apdu);
    const ack = try service.ReadPropertyAck.decode(try back_a.serviceData());
    try testing.expectEqual(@as(f32, 72.5), (try ack.scalar()).real);
}

test "the module's own client and device interoperate over a simulated network" {
    var net: LoopNetwork = .{};
    var client_ep = LoopTransport.init(.{ .ip = .{ 192, 0, 2, 1 } });
    var device_ep = LoopTransport.init(.{ .ip = .{ 192, 0, 2, 2 } });
    net.attach(&client_ep);
    net.attach(&device_ep);

    var dev_props = [_]Property{
        .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .device, .instance = 42 } } },
        .{ .id = .object_name, .value = .{ .string = "SIM" } },
    };
    var ai_props = [_]Property{
        .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .analog_input, .instance = 1 } } },
        .{ .id = .present_value, .value = .{ .real = 19.5 }, .cov_reported = true },
    };
    var objects = [_]Object{
        .{ .id = .{ .type = .device, .instance = 42 }, .properties = &dev_props },
        .{ .id = .{ .type = .analog_input, .instance = 1 }, .properties = &ai_props },
    };
    var dev = Device.init(device_ep.transport(), .{ .instance = 42 }, &objects);
    var c = Client.init(client_ep.transport(), .{});

    try c.whoIs(null, null);
    _ = try dev.poll(0);
    const found = try c.poll(0);
    try testing.expectEqual(@as(u22, 42), found.i_am.info.device.instance);

    const id = try c.readProperty(
        found.i_am.from,
        .{ .type = .analog_input, .instance = 1 },
        .present_value,
        null,
        1,
    );
    _ = try dev.poll(1);
    const ev = try c.poll(2);
    try testing.expectEqual(id, ev.complex_ack.invoke_id);
    const ack = try service.ReadPropertyAck.decode(ev.complex_ack.data);
    try testing.expectEqual(@as(f32, 19.5), (try ack.scalar()).real);
}

test "BACnet/SC end to end: two nodes and a hub, no sockets at all" {
    // The BACnet/IP test above rides a simulated UDP network; this one rides
    // nothing — the hub and both nodes are pure state machines, and the "wire"
    // is the caller moving byte slices between them. That is the whole point
    // of the time-injected design, and it is what makes the 300-second timers
    // testable.
    var prng = std.Random.DefaultPrng.init(0xBAC05C);
    const rand = prng.random();

    var hub = ScHub.init(.{
        .vmac = .{ .octets = .{ 0xFE, 0, 0, 0, 0, 1 } },
        .uuid = Uuid.random(rand),
        .websocket_uris = "wss://192.0.2.1/",
    }, rand);

    var a = ScNode.init(.{
        .vmac = .{ .octets = .{ 1, 1, 1, 1, 1, 1 } },
        .uuid = Uuid.random(rand),
        .primary_uri = "wss://192.0.2.1/",
    }, rand);
    var b = ScNode.init(.{
        .vmac = .{ .octets = .{ 2, 2, 2, 2, 2, 2 } },
        .uuid = Uuid.random(rand),
        .primary_uri = "wss://192.0.2.1/",
    }, rand);

    // Both nodes dial in. The hub hands out connection ids; the caller is the
    // one holding the sockets, so it is the one that pairs them up.
    const conn_a = try hub.accept(0);
    const conn_b = try hub.accept(0);
    _ = a.start(0);
    _ = b.start(0);
    _ = try a.onWebSocketOpen(0);
    _ = try b.onWebSocketOpen(0);

    // Drive each Connect-Request into the hub and the Connect-Accept back.
    for ([_]struct { node: *ScNode, conn: usize }{
        .{ .node = &a, .conn = conn_a },
        .{ .node = &b, .conn = conn_b },
    }) |peer| {
        const request = peer.node.nextOutgoing().?;
        _ = try hub.onMessage(0, peer.conn, request);
        const accept = hub.nextOutgoing().?;
        try testing.expectEqual(peer.conn, accept.conn);
        _ = try peer.node.onMessage(0, accept.bytes);
        try testing.expectEqual(sc_node.State.connected, peer.node.state);
    }
    try testing.expectEqual(@as(usize, 2), hub.nodeCount());

    // A broadcast Who-Is from A must reach B — with A's VMAC filled in by the
    // hub, because A never sent one.
    const who_is = [_]u8{ 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08 };
    try a.sendNpdu(Vmac.broadcast, &who_is);
    _ = try hub.onMessage(1, conn_a, a.nextOutgoing().?);
    const relayed = hub.nextOutgoing().?;
    try testing.expectEqual(conn_b, relayed.conn);
    const at_b = try b.onMessage(1, relayed.bytes);
    try testing.expectEqualSlices(u8, &who_is, at_b.npdu.bytes);
    try testing.expect(at_b.npdu.source.?.eql(a.config.vmac));

    // ... and B's unicast answer must come back to A and to nobody else.
    const i_am = [_]u8{ 0x01, 0x00, 0x10, 0x00, 0xC4, 0x02, 0x00, 0x02, 0x57 };
    try b.sendNpdu(a.config.vmac, &i_am);
    _ = try hub.onMessage(2, conn_b, b.nextOutgoing().?);
    const answer = hub.nextOutgoing().?;
    try testing.expectEqual(conn_a, answer.conn);
    try testing.expectEqual(@as(?sc_hub.Outgoing, null), hub.nextOutgoing());
    const at_a = try a.onMessage(2, answer.bytes);
    try testing.expectEqualSlices(u8, &i_am, at_a.npdu.bytes);

    // A heartbeat from A is answered by the hub and accepted by A.
    _ = try a.poll(150_000);
    _ = try hub.onMessage(150_000, conn_a, a.nextOutgoing().?);
    _ = try a.onMessage(150_001, hub.nextOutgoing().?.bytes);
    try testing.expectEqual(sc_node.State.connected, a.state);

    // A leaves politely; the hub acknowledges and forgets it.
    _ = try a.stop(200_000);
    const ev = try hub.onMessage(200_000, conn_a, a.nextOutgoing().?);
    try testing.expectEqual(sc_hub.DisconnectReason.peer_request, ev.node_disconnected.reason);
    _ = try a.onMessage(200_001, hub.nextOutgoing().?.bytes);
    try testing.expectEqual(sc_node.State.stopped, a.state);
    try testing.expectEqual(@as(usize, 1), hub.nodeCount());
}

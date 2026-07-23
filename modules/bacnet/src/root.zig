// SPDX-License-Identifier: MIT

//! bacnet — pure-Zig **BACnet/IP (ASHRAE 135)**: the building-automation
//! protocol that HVAC, lighting, access control and fire panels speak to a
//! building-management system.
//!
//! Four wire layers, each usable on its own, plus the two roles:
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
//!
//! Verified against **byte-exact goldens from an independent implementation**
//! and by **live round trips in both directions** against it; see
//! `goldens.zig`, `interop.zig` and SPEC.md for exactly what came from where.
//!
//! Provenance: clean-room from ASHRAE 135's documented encodings. A
//! third-party stack was used as a black-box oracle and a live peer; one
//! function of its source was read while probing its API. See SPEC.md and
//! `/NOTICE`.

const std = @import("std");

pub const meta = .{
    // Every codec, the client and the device are pure computation; only the
    // optional UdpTransport touches std.Io.net.
    .platform = .any,
    .role = .both, // client + device (responder)
    // One Client/Device owns its transaction table, subscriptions and
    // buffers; nothing shared or global. Concurrency and the clock belong to
    // the caller.
    .concurrency = .single_owner,
    .model_after = "ASHRAE 135 (BACnet) Annex J + clauses 6, 15, 16, 20; wire behaviour byte-compared against bacpypes3 and validated by live round trips in both directions (see SPEC.md)",
    .deps = .{"netaddr"},
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
/// Byte-exact goldens from an independent implementation.
pub const goldens = @import("goldens.zig");
/// Live interop tests, gated on an environment variable.
pub const interop = @import("interop.zig");

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
    _ = goldens;
    _ = interop;
}

// ── tests: the stack end to end ────────────────────────────────────────────

const testing = std.testing;

test "meta names its one sibling dependency" {
    try testing.expectEqual(@as(usize, 1), meta.deps.len);
    try testing.expectEqualStrings("netaddr", meta.deps[0]);
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

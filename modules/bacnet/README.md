# bacnet

Pure-Zig **BACnet/IP (ASHRAE 135)**: the building-automation protocol that
HVAC, lighting, access control and fire panels speak to a building-management
system. A typed, allocation-free wire codec for all four layers, a
transport-agnostic client, and a device (responder) that doubles as a
fleet-simulation target.

- No pure-Zig BACnet library exists; the field is C (`bacnet-stack`) and
  Python (`bacpypes3`).
- **Platform:** any (every codec, the client and the device are pure
  computation; only the optional `UdpTransport` adapter touches `std.Io.net`).
- **Model after:** ASHRAE 135 (BACnet) Annex J + clauses 6, 15, 16, 20, with
  wire behaviour byte-compared against `bacpypes3` and validated by live round
  trips in **both** directions (see SPEC.md).

## Scope

- **`bvll`** (Annex J) — the BACnet/IP virtual link layer: the four-octet
  `81 | function | length` header on every datagram, with the length checked
  against the datagram the socket actually delivered.
  `Original-Unicast-NPDU`, `Original-Broadcast-NPDU`, `Forwarded-NPDU`,
  `Distribute-Broadcast-To-Network`, and the BBMD/foreign-device functions
  (`Register-Foreign-Device`, read/write of the broadcast-distribution table,
  read of the foreign-device table) with iterators over their entries. Default
  port 47808 (`0xBAC0`). Addresses go through the sibling `netaddr` module.
- **`npdu`** (clause 6) — the network layer, whose **layout is decided by the
  control octet**: whether DNET/DLEN/DADR are present, whether SNET/SLEN/SADR
  are, and whether a hop count follows (it does iff the *destination* bit is
  set, even though it sits after the *source* fields). `DLEN = 0` is a legal
  broadcast; `SLEN = 0` is malformed and refused. Plus the network-layer
  messages — `Who-Is-Router-To-Network`, `I-Am-Router-To-Network`,
  `I-Could-Be-Router-To-Network`, `Reject-Message-To-Network` typed, the rest
  passed through with their vendor id.
- **`apdu`** (clause 20.1) — all eight PDU types: `Confirmed-Request` (with
  SEG/MOR/SA, max-segments, max-APDU, invoke id, sequence number and window
  size), `Unconfirmed-Request`, `SimpleACK`, `ComplexACK`, `SegmentACK`,
  `Error`, `Reject`, `Abort`. **Segmentation is parsed, never guessed**: the
  SEG bit moves the service choice two octets, and a segmented PDU comes back
  as a typed segment whose `serviceData()` returns `error.Segmented` rather
  than a plausible-looking wrong decode.
- **`tag`** (clause 20.2) — **the heart of BACnet**, in its own file: the
  application/context class bit, the tag-number escape (>14 costs a second
  octet), the length/value/type field with its 5 / 254 / 65535 escapes, the
  Boolean-in-LVT special case, opening/closing brackets for constructed data,
  and every primitive — Null, Boolean, Unsigned, Signed, Real, Double,
  OctetString, CharacterString **with its encoding octet**, BitString **with
  its unused-bits count**, Enumerated, Date, Time and ObjectIdentifier
  (10-bit type + 22-bit instance). `Reader`/`Writer` walk and build a tagged
  stream over a caller-supplied buffer.
- **`types`** — object types, property identifiers (including the
  `ALL`/`REQUIRED`/`OPTIONAL` wildcards), confirmed and unconfirmed service
  choices, error classes and codes, reject and abort reasons, and the common
  enumerations. All **non-exhaustive**: a vendor value round-trips numerically
  rather than being refused.
- **`service`** (clauses 15/16) — `ReadProperty`, `ReadPropertyMultiple` (with
  builders and iterators for its list-of-lists shape and its per-property
  errors), `WriteProperty` (with the **priority array** and the `NULL`
  relinquish), `Who-Is`/`I-Am`, `Who-Has`/`I-Have`, `SubscribeCOV` with both
  notification forms, and `ReadRange` with all three range selectors. Property
  *values* are never interpreted: their datatype comes from the property, not
  the wire, so they are handed back as raw tagged octets.
- **`client`** — discover devices, read and write properties, subscribe to
  COV. **Pure and time-injected**: the caller supplies `now_ms`, so the APDU
  timeout and retry ladder are testable with a fake clock. Invoke ids are
  never reused while outstanding; a segmented response is answered with
  `Abort(segmentation_not_supported)` and reported, never mis-parsed.
- **`device`** — a small object database that answers Who-Is, Who-Has,
  ReadProperty, ReadPropertyMultiple (including the wildcards), WriteProperty
  and SubscribeCOV, emits COV notifications on change, expires subscriptions,
  and answers a unicast question with a unicast reply. Stand one up per
  simulated device.
- Hostile input never panics anywhere: a BVLC length that disagrees with the
  datagram, control bits promising fields the buffer lacks, a tag whose
  extended length runs past the end, an unclosed context tag, a reserved
  object type, an unknown character-string encoding, a BitString claiming more
  unused bits than exist and a segmented ComplexACK are all typed errors.

## Use

```zig
const bacnet = @import("bacnet");

// ── client ──────────────────────────────────────────────────────────────────
var udp = try bacnet.UdpTransport.open(io, .{ .port = 47808 });
defer udp.close();
udp.setRecvTimeout(100);

var c = bacnet.Client.init(udp.transport(), .{});

try c.whoIs(null, null);                       // discovery broadcast
// or, for a device whose address you know but cannot broadcast onto:
try c.whoIsTo(addr, null, null);

const id = try c.readProperty(
    addr,
    .{ .type = .analog_input, .instance = 5 },
    .present_value,
    null,                                       // no array index
    now,
);

while (true) : (now += 100) {
    switch (try c.poll(now)) {
        .i_am => |e| discovered(e.from, e.info.device.instance),
        .complex_ack => |e| {
            const ack = try bacnet.service.ReadPropertyAck.decode(e.data);
            std.debug.print("{d}\n", .{(try ack.scalar()).real});
        },
        .err => |e| std.debug.print("{t}/{t}\n", .{ e.class, e.code }),
        .timeout => |e| retryOrGiveUp(e.invoke_id),
        else => {},
    }
    _ = id;
}

// Writing: build the value with a tag.Writer, then hand over the octets.
var vbuf: [8]u8 = undefined;
var vw = bacnet.tag.Writer.init(&vbuf);
try vw.appReal(21.0);
_ = try c.writeProperty(addr, setpoint, .present_value, null, vw.written(), 8, now);

// Relinquishing priority 8 (writing NULL there) is its own operation:
_ = try c.relinquish(addr, setpoint, .present_value, 8, now);

// Several objects and properties in one round trip, wildcards included:
_ = try c.readPropertyMultiple(addr, &.{
    .{ .object = sensor, .properties = &.{
        .{ .property = .present_value },
        .{ .property = .status_flags },
    } },
    .{ .object = device_obj, .properties = &.{.{ .property = .required }} },
}, now);

// ── device (fleet-simulation target) ────────────────────────────────────────
var ai_props = [_]bacnet.Property{
    .{ .id = .object_identifier, .value = .{ .object_id = .{ .type = .analog_input, .instance = 5 } } },
    .{ .id = .object_name, .value = .{ .string = "ZONE-TEMP" } },
    .{ .id = .present_value, .value = .{ .real = 72.5 }, .cov_reported = true },
    .{ .id = .status_flags, .value = .{ .bit_string = .{ .unused_bits = 4, .bytes = &.{0x00} } }, .cov_reported = true },
};
var objects = [_]bacnet.Object{
    .{ .id = .{ .type = .device, .instance = 599 }, .properties = &dev_props },
    .{ .id = .{ .type = .analog_input, .instance = 5 }, .properties = &ai_props },
};
var dev = bacnet.Device.init(udp.transport(), .{ .instance = 599 }, &objects);

try dev.announce();                            // unsolicited I-Am on start-up
while (true) : (now += 100) {
    _ = try dev.poll(now);
    // Driving a simulation: this notifies every COV subscriber automatically.
    try dev.update(sensor, .present_value, .{ .real = readSensor() }, now);
}
```

The pure layers are usable on their own — `bvll.decode`/`encode` for a
datagram, `npdu.decode`/`encode` for the network layer, `apdu.decode`/`encode`
for a PDU, and `tag.Reader`/`tag.Writer` for anything tagged, including
services this module does not model.

## Verify

```
zig build test-bacnet                          # Debug
zig build test-bacnet -Doptimize=ReleaseFast
zig fmt --check modules/bacnet
```

129 tests, of which 121 are fully offline. The eight live tests skip
gracefully (printing `SKIPPED:` and passing) when no peer is present:

```
BACNET_TEST_DEVICE=host:port    # our client -> a real BACnet device
BACNET_TEST_LISTEN=host:port    # a real BACnet client -> our device
```

The offline suite includes **42 byte-exact datagram goldens plus 47 primitive
tag goldens generated by `bacpypes3`**, an independent BACnet stack — every
one of them decodes, re-encodes to the identical octets from its *decoded*
fields, and is asserted field by field. On top of that: full client↔device
round trips over an in-memory network, the APDU timeout and retry ladder under
a fake clock, and `std.testing.fuzz` sweeps over the tag decoder, the BVLC
decoder, the NPDU decoder, the APDU decoder, every service decoder and the
device's request handler. See SPEC.md for what is third-party-validated versus
self-derived, what ran live, and what is deferred.

Provenance: clean-room from ASHRAE 135's documented encodings. `bacpypes3` was
used as a black-box test oracle and as a live peer; one function of its source
was read while probing its API — see SPEC.md and `/NOTICE`.

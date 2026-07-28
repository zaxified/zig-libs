# enip

Pure-Zig **EtherNet/IP with CIP** (the Common Industrial Protocol): the
protocol every Allen-Bradley controller — and most of the industrial Ethernet
devices around one — speaks on TCP 44818 and UDP 2222/44818. A typed,
allocation-free wire codec for the whole stack (encapsulation → CPF → CIP
Message Router → Connection Manager → Logix tag services), a
transport-agnostic client, a symbolic tag-path parser for the
`Program:Main.MyUDT.Member[3]` notation, and an adapter that doubles as a
fleet-simulation target.

- No pure-Zig EtherNet/IP library exists; the field is C (OpENer, EIPScanner)
  and Python (`pycomm3`, `cpppo`).
- **Platform:** any (the codecs, the client's logic and the adapter are pure
  computation; only the optional `TcpTransport` / `UdpDiscovery` adapters touch
  `std.Io.net`).
- **Model after:** ODVA CIP Volume 1 (Common Industrial Protocol) and Volume 2
  (EtherNet/IP Adaptation), with wire behaviour cross-checked against captured
  traffic between three independent third-party stacks, against Wireshark's own
  `enip`/`cip` dissector, and verified by live round trips in both directions
  (see SPEC.md).

## Scope

- **`encap`** (Vol 2 ch. 2) — the 24-octet encapsulation header. Its length
  field counts the data **after** the header (unlike TPKT's, which counts
  itself), everything is little-endian **except** the `sockaddr_in` fields
  inside identity and sockaddr items, and `sender_context` is eight opaque
  octets echoed verbatim — the only request/response correlation the protocol
  has. Commands: `NOP`, `ListServices`, `ListIdentity`, `ListInterfaces`,
  `RegisterSession`, `UnRegisterSession`, `SendRRData`, `SendUnitData`. Plus
  `Framer`, a stream splitter, because TCP gives no message boundaries.

  `ListIdentity` over **UDP broadcast** is how devices are discovered; the CIP
  identity item (vendor, device type, product code, revision, status, serial,
  product name, state) is modelled in full.
- **`cpf`** — the Common Packet Format item list every CIP message rides in:
  Null Address, Connected Address, Unconnected Data, Connected Data, Sequenced
  Address and the two Sockaddr Info items. The **ordering rules are enforced**,
  not assumed: an address item first, a data item second, a connected address
  paired only with connected data. A connected data item begins with a
  **two-octet sequence count** that belongs to the item and not to CIP.
- **`epath`** (Vol 1 App. C) — logical segments for class, instance,
  attribute, member and connection point in 8/16/32-bit forms **with their pad
  rules** (padded and packed are both supported and are an explicit choice,
  never a guess), ANSI Extended Symbol segments for tag names padded to even,
  port segments for routing (including the extended-port and extended-link
  forms), network segments and the electronic key. The path size is counted in
  **words**, and an odd path is a typed error rather than a silent round-up.
- **`cip`** — the Message Router request and reply. A reply sets **bit 7 of the
  service code**; `additional_status_size` is counted in words and is
  attacker-controlled, so it is bounds-checked. `Get_Attribute_Single`,
  `Set_Attribute_Single`, `Get_Attributes_All`, `Get_Attribute_List`,
  `Set_Attribute_List`, `Reset`, and `Multiple_Service_Packet` (0x0A) whose
  **offset table is measured from the start of the count field**.

  **Service codes are only unique within a class.** `0x52` is
  `Unconnected_Send` on the Connection Manager and `Read Tag Fragmented`
  everywhere else; `0x4E` is `Forward_Close` or `Read Modify Write Tag`.
  Nothing here maps a bare service code to a name without the path.
- **`connmgr`** — the Connection Manager (class 0x06): `Unconnected_Send`
  (0x52) with its route path and its `2^tick × ticks` timeout (`tick=5,
  ticks=157` is 5024 ms, not 157), `Forward_Open` (0x54),
  `Large_Forward_Open` (0x5B), `Forward_Close` (0x4E), the connection
  parameters in both their 16- and 32-bit layouts, the RPI, and the
  `{connection serial, originator vendor, originator serial}` triple a close
  matches on.
- **`types`** — the CIP elementary types (BOOL, SINT/INT/DINT/LINT and the
  unsigned forms, REAL, LREAL, STRING/SHORT_STRING, BYTE/WORD/DWORD/LWORD…)
  with their codes, and the Logix tag services `Read Tag` (0x4C), `Write Tag`
  (0x4D), `Read Tag Fragmented` (0x52) and `Write Tag Fragmented` (0x53). A
  structure read answers `A0 02` followed by a **structure handle** that is not
  data; a fragmented read's offset is in **octets**, not elements.
- **`tagpath`** — the notation every Logix tool takes: `MyTag`, `MyArray[3]`,
  `Matrix[1,2,3]`, `MyUDT.Member`, `Program:MainProgram.MyTag` (one symbol
  segment, colon included). Malformed forms (`Tag[`, `Tag[]`, `Tag[a]`,
  `Ta__g`, `Tag_`, `1Tag`, `A..B`, four dimensions, a 41-character name) are
  typed errors, never a silently wrong path.
- **`client`** — register/unregister a session, `ListIdentity` (TCP and UDP
  discovery), `ListServices`, `ListInterfaces`, read and write tags by
  symbolic name, fragmented read and write, `Multiple_Service_Packet`
  batching, the attribute services, and Class 3 connected messaging via
  `Forward_Open` / `Forward_Close`.
- **`adapter`** — the target side as a pure function from one message to one
  message, backed by caller-owned tag storage. Stand one up per simulated
  device for fleet simulation.
- Hostile input never panics anywhere: an encapsulation length disagreeing
  with the payload, a CPF item count that overruns, an item length pointing
  past the buffer, an EPATH segment running past the path, a symbolic segment
  with an odd length and no pad, a Multiple Service Packet offset table
  pointing outside the payload, an additional-status count that overruns and a
  tag read whose type code contradicts the data length are all typed errors.

## Use

```zig
const enip = @import("enip");

// ── client ──────────────────────────────────────────────────────────────────
var tt = try enip.TcpTransport.connect(io, address); // or any Transport impl
defer tt.close();

var buf: [16384]u8 = undefined;
var plc = try enip.Client.init(tt.transport(), &buf, .{
    // A ControlLogix chassis needs a route; a leaf device needs `.direct`.
    .routing = .{ .unconnected_send = &enip.connmgr.backplane_slot_0 },
});
_ = try plc.registerSession();
defer plc.unregisterSession() catch {};

// Who am I talking to?
const ident = try plc.listIdentity();
std.debug.print("{s} rev {d}.{d}\n", .{
    ident.product_name, ident.revision_major, ident.revision_minor,
});

// Read a tag by name. The octets point into the client's buffer.
const td = try plc.readTag("MyArray[3]", 1);
std.debug.print("{d}\n", .{(try td.at(0)).asInt().?});

// Write one.
var value: [4]u8 = undefined;
std.mem.writeInt(i32, &value, 1234, .little);
try plc.writeTag("Program:MainProgram.Counter", .dint, 1, &value);

// A tag bigger than one reply, reassembled over as many exchanges as it takes.
var big: [4096]u8 = undefined;
const all = try plc.readTagFragmented("BigArray[0]", 2000, &big);

// Several tags in one round trip; a per-tag failure is reported, not thrown.
const names = [_][]const u8{ "A", "B", "C" };
var results: [3]?enip.TagData = undefined;
_ = try plc.readTags(&names, &results);

// Connected (Class 3) messaging.
_ = try plc.forwardOpen(.{ .size = 500 });
defer plc.forwardClose() catch {};
var req: [64]u8 = undefined;
const reply = try plc.sendConnectedCip(try enip.client.encodeReadTag("A", 1, &req));

// ── discovery (UDP broadcast) ───────────────────────────────────────────────
var disc = try enip.UdpDiscovery.open(io, .{});
defer disc.close();
disc.setRecvTimeout(1000);
var dreq: [32]u8 = undefined;
try disc.send(
    enip.UdpDiscovery.limited_broadcast,
    enip.default_port,
    try enip.encodeListIdentityRequest("zig-enip".*, &dreq),
);
var dbuf: [1024]u8 = undefined;
while (try disc.receive(&dbuf)) |dgram| {
    const who = try enip.decodeListIdentityReply(dgram.bytes);
    report(dgram.from_ip, who);
}

// ── adapter (fleet-simulation target) ───────────────────────────────────────
var scada: [200]u8 = @splat(0);
var tags = [_]enip.TagBinding{
    .{ .name = "SCADA", .type = .int, .bytes = &scada },
};
var device = enip.Adapter.init(.{ .product_name = "sim-1" }, &tags);

var in: [8192]u8 = undefined;
var out: [8192]u8 = undefined;
while (true) {
    const n = try link.read(&in);
    const reply = (try device.handle(in[0..n], &out)) orelse continue;
    try link.write(reply);
}
```

The pure layers are usable on their own — `encap.decode`/`encap.Framer` for
framing, `cpf.decode` for the item list, `epath.Iterator`/`epath.Builder` for
paths, `cip.Request`/`cip.Reply` for the Message Router, `connmgr` for the
Connection Manager and `tagpath.parse` for the notation, with your own I/O.

## Safety

EtherNet/IP is **unauthenticated and unencrypted** by design: anyone with a
path to TCP 44818 can read and write any tag. `Reset` on the Identity object
reboots a device, and `writeTag` on a running machine changes what it is
doing. Nothing here calls either implicitly, the adapter refuses `Reset`
unless `allow_reset` is set, and CIP Security is **not** implemented — put
transport security underneath, exactly as the repo's BYO-TLS rule
(CONVENTIONS §2) prescribes. See SPEC.md, "Threat model".

## Verify

```
zig build test-enip                          # Debug
zig build test-enip -Doptimize=ReleaseFast
zig fmt --check modules/enip
```

The suite runs fully offline except for a few live tests, which skip
gracefully (printing `SKIPPED:` and passing) when no peer is present:

```
# our client -> a real EtherNet/IP target
ENIP_TEST_SERVER=127.0.0.1:44818 ENIP_TEST_TAG=SCADA ENIP_TEST_DINT_TAG=TestTag \
  zig build test-enip
# add ENIP_TEST_ROUTE=direct for a device that does not route

# connected (Class 3) messaging against the same target
ENIP_TEST_CONNECTED=127.0.0.1:44818 zig build test-enip

# a real EtherNet/IP client -> our adapter
ENIP_TEST_LISTEN=127.0.0.1:44830 zig build test-enip
```

The offline suite includes **61 byte-exact goldens captured from real traffic
between three independent third-party implementations** — every one decodes
and re-encodes to the identical octets, every CIP path is rebuilt from its
*decoded segments*, and a coverage assertion fails if the table stops
containing any command, item type, service or routing shape — plus full
client↔adapter round trips over an in-memory wire and `std.testing.fuzz`
sweeps over every decoder, the tag-path parser, the client's reply handling
and the adapter's request handler. See SPEC.md for what is third-party
validated versus self-derived, and what is deferred.

Provenance: clean-room from the published ODVA CIP Volume 1 / Volume 2 frame
layouts. No third-party source was consulted as a design reference;
third-party stacks and Wireshark's dissector were used as black-box test
oracles and as live peers only. See SPEC.md and `/NOTICE`.

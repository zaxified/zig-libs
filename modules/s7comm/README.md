# s7comm

Pure-Zig **Siemens S7 communication over ISO-on-TCP**: the protocol STEP 7,
WinCC and every third-party S7 driver speak to S7-300, S7-400, S7-1200 and
S7-1500 CPUs on TCP port 102. A typed, allocation-free wire codec for the whole
stack (TPKT → COTP → S7comm), a transport-agnostic client, an address parser for
the conventional `DB1.DBW20` notation, and a responder that doubles as a
fleet-simulation target.

- No pure-Zig S7 library exists; the field is C (`snap7`, `libnodave`) and its
  bindings.
- **Platform:** any (the codecs, the client's PDU logic and the responder are
  pure computation; only the optional `TcpTransport` adapter touches
  `std.Io.net`).
- **Model after:** ISO 8073 class 0 / RFC 1006 plus the S7comm frame layouts,
  with wire behaviour cross-checked against captured traffic between two
  independent third-party stacks and verified by live round trips in both
  directions (see SPEC.md).

## Scope

- **`tpkt`** (RFC 1006 §6) — the four-octet shim: version 3, a reserved octet
  and a 16-bit length that **counts the header itself**. Plus `Framer`, a
  stream splitter, because TCP gives no message boundaries.
- **`cotp`** (ISO 8073 / X.224 class 0) — `CR`/`CC` connection setup with the
  source and destination TSAPs and the TPDU size, `DT` data with its TPDU
  number and EOT bit, `DR`/`DC`/`ER`. The length indicator counts the octets
  after itself excluding user data, which is what puts the S7 PDU at the right
  offset.

  **Rack and slot are not protocol fields.** What every tool calls *rack 0,
  slot 2* is the destination TSAP `{connection type, rack * 0x20 + slot}` —
  `Tsap.rackSlot(.pg, 0, 2)`. A wrong slot produces no error message anywhere
  in the S7 layer: the CPU just refuses the transport connection.
- **`s7`** — the S7comm header: protocol id `0x32`, ROSCTR (Job / Ack /
  Ack-Data / Userdata), redundancy id, PDU reference, parameter and data
  lengths, and for an Ack or Ack-Data **two extra error octets** — so the
  header is 10 octets on a request and 12 on a reply. Plus `Setup
  communication` (maximum AmQ calling/called and the negotiated PDU length),
  which is a first-class property: everything afterwards is bounded by it.
- **`items` / `vars`** — Read Var and Write Var. The `S7ANY` item specification
  (transport size, element count, DB number, area — DB/instance-DB/M/I/Q/T/C/
  local/peripheral — and the three address octets that are a **bit address**,
  `byte * 8 + bit`, except for timers and counters where they are an element
  index). Multi-item requests, per-item return codes, and the data block whose
  length field is counted in **bits for `bit`/`byte_word_dword`/`int` and in
  octets for `dint`/`real`/`octet_string`**, with an arbitrary pad octet
  between items and none after the last. A failed item is four octets with no
  payload at all.
- **`userdata`** — the second request shape (ROSCTR 7) with its own
  sub-header: `Read SZL` for the system status list, including `0x0011`
  (module identification), `0x001C` (component identification) and `0x0424`
  (operating mode, i.e. run/stop).
- **`address`** — the STEP 7 notation every S7 tool takes: `DB1.DBW20`,
  `DB1.DBX0.3`, `M10.2`, `MB10`, `I0.0`, `E0.7`, `QW4`, `AB4`, `T5`, `C3`,
  `Z3`, `PIW256`, `PQB8`. Malformed forms (`DB1.DBX0.8`, `M10.8`, `DB0.DBW0`,
  `MB10.1`, `DB1.DBW20junk`) are typed errors, never a silently wrong address.
- **`client`** — connect (COTP + Setup), read/write by item, by area with
  automatic splitting over the negotiated PDU, by STEP 7 address or by single
  bit; multi-item read and write; `Read SZL`; CPU status; disconnect. Plus the
  PLC control services (**stop, warm restart, cold restart**) behind explicit
  names — see "Safety" below.
- **`server`** — a `Responder`: the PLC side as a pure function from one packet
  to one packet, backed by caller-owned byte slices. Stand up one per simulated
  CPU for fleet simulation. PLC control is **refused by default**.
- **`s7plus`** — **S7CommPlus** (protocol id `0x72`), the dialect the S7-1200
  and S7-1500 actually speak, on the *same* TPKT/COTP transport. A different
  protocol, added as a separate namespace so classic S7comm is untouched:
  - **`s7plus.value`** — the typed-value TLV codec that is the heart of the
    protocol: a base-128 big-endian VLQ (signed and unsigned), every scalar
    datatype (bool, U/SInt…U/LInt, Real/LReal, Timestamp, blob, WString), and
    structs/arrays/variants with **bounded recursion** and a hostile
    deeply-nested guard.
  - **`s7plus`** — the `0x72` PDU frame: the header (protocol id, PDU type
    Connect/Data/Data-with-integrity/Keep-alive, data length), the trailing
    integrity part, and the trailer (a second `0x72` header form that closes a
    Data PDU).
  - **`s7plus.object`** — the object/attribute stream, the Data-PDU inner
    header (opcode, function — CreateObject/Get/SetVariable/…, sequence
    number), and the **session / sequence / integrity-id** model: the running
    anti-replay value newer firmware verifies must strictly progress.
  - **`s7plus.path`** — the S7-1200/1500 **symbolic** address parser
    (`"MotorData".Axis[2].Position`), with every malformed form a typed error.
  - **`s7plus.client`** — a codec-driven client and responder over the shared
    `Transport` seam (Connect → Get/SetVariable). See "S7CommPlus is
    codec-driven" below and SPEC.md for what that does and does not prove.
- Hostile input never panics anywhere: a truncated TPKT, a TPKT length that
  disagrees with the payload, a COTP length indicator pointing past the buffer,
  an S7 header whose parameter and data lengths overflow the frame, an item
  count that disagrees with the payload, a length that contradicts its
  transport size and a reply whose per-item return code is an error while data
  is present are all typed errors.

## Use

```zig
const s7comm = @import("s7comm");

// ── client ──────────────────────────────────────────────────────────────────
var tt = try s7comm.TcpTransport.connect(io, address); // or any Transport impl
defer tt.close();

var buf: [s7comm.Client.bufferSize(480)]u8 = undefined;
var plc = try s7comm.Client.init(tt.transport(), &buf, .{
    // rack and slot live here, and nowhere else
    .remote_tsap = s7comm.Tsap.rackSlot(.pg, 0, 2),
    .requested_pdu_length = 480,
});
try plc.connect();
defer plc.disconnect();
std.debug.print("negotiated PDU: {d}\n", .{plc.pduLength()});

// By STEP 7 address.
var word: [2]u8 = undefined;
_ = try plc.readAddress("DB1.DBW20", 1, &word);
try plc.writeAddress("DB1.DBW20", 1, &[_]u8{ 0x12, 0x34 });

// A single bit: M10.2 := true.
try plc.writeBit(.flags, 0, 10, 2, true);

// A whole area, split across as many PDUs as the negotiated size needs.
var block: [600]u8 = undefined;
_ = try plc.readBytes(.db, 9, 0, &block);

// Several items in one PDU; a failed item is reported, not thrown.
const list = [_]s7comm.Item{
    try s7comm.Item.at(.db, 1, 20, 0, .byte, 4),
    try s7comm.Item.at(.flags, 0, 0, 0, .byte, 2),
};
var payloads: [64]u8 = undefined;
var results: [2]s7comm.ItemResult = undefined;
for (try plc.readMulti(&list, &payloads, &results)) |r| {
    if (r.return_code.isSuccess()) use(r.payload) else report(r.return_code);
}

// CPU identification and state.
const szl = try plc.readSzl(s7comm.SzlId.module_identification, 0);
const state = try plc.cpuStatus(); // .run / .stop

// ── responder (fleet-simulation target) ─────────────────────────────────────
var db1: [256]u8 = @splat(0);
var flags: [128]u8 = @splat(0);
var areas = [_]s7comm.AreaBinding{
    .{ .area = .db, .db_number = 1, .bytes = &db1 },
    .{ .area = .flags, .bytes = &flags },
};
var cpu = s7comm.Responder.init(.{ .max_pdu_length = 480 }, &areas);

var in: [2048]u8 = undefined;
var out: [2048]u8 = undefined;
while (true) {
    const n = try link.read(&in);
    const reply = (try cpu.handle(in[0..n], &out)) orelse break;
    try link.write(reply);
}
```

The pure layers are usable on their own — `tpkt.decode`/`tpkt.Framer` for
framing, `cotp.decode` for a TPDU, `s7.decode` for a PDU,
`items.Item`/`items.DataItemIterator` for variable accesses, and
`address.parse` for the notation, with your own I/O.

## Safety

S7comm is **unauthenticated and unencrypted**. `plcStop`, `plcHotStart` and
`plcColdStart` will stop or restart a running machine, and a cold restart
clears retentive data. They are exposed because a diagnostic tool and a
simulator both need them, but nothing in this module calls them implicitly, the
responder refuses them unless `allow_plc_control` is set, and they must never
be pointed at equipment you do not own. See SPEC.md, "Threat model".

## S7CommPlus is codec-driven, not peer-validated

The classic layers were validated against **real traffic between two
independent third-party stacks** and by **live round trips**. S7CommPlus was
not, and this matters:

- **No live peer.** snap7 (the classic reference) does **not** implement
  S7CommPlus, and no S7-1200/1500 or open S7CommPlus simulator was obtainable
  here. So there is no interop test, and none is faked.
- **No `s7comm-plus` dissector.** This environment's Wireshark 4.6.4 ships the
  classic `s7comm` dissector but **not** `s7comm-plus` (confirmed by inspecting
  `libwireshark`), so `rawshark` cannot field-decode a `0x72` body. It **can**
  and does confirm the *envelope*: for a full frame this module builds,
  `tpkt.length`, `cotp.type` (a class-0 DT) and the COTP→`0x72` payload boundary
  all check out.
- **What is validated:** the value/datatype codec and the header layout against
  the documented `s7comm-plus` field structure; everything by exact round-trip
  and byte-pinned goldens; hostile input and `std.testing.fuzz` over every
  decoder; and a full client↔responder round trip (Connect, Set/GetVariable,
  and the integrity anti-replay check) over an in-memory wire.
- **Codec-only vs driven:** the codecs, framing, path parser and
  session/integrity model are complete and exercised; the client/responder
  *choreography* is a self-consistent model, **not** a validated S7-1200 driver.
  Treat the responder as a fleet-simulation target, like the classic one.

See SPEC.md, "S7CommPlus", for the field-by-field breakdown and the honest
remaining list (encryption, the newest-firmware integrity cryptography,
subscriptions, symbolic sub-path resolution, block up/download).

## Verify

```
zig build test-s7comm                          # Debug
zig build test-s7comm -Doptimize=ReleaseFast
zig fmt --check modules/s7comm
```

161 tests, of which 159 are fully offline (the classic suite plus the
S7CommPlus codec, framing, path, session/integrity and client↔responder round
trips). The two live tests — both classic S7comm — skip gracefully (printing
`SKIPPED:` and passing) when no peer is present:

```
# our client -> a real S7 server (e.g. a snap7 server on an unprivileged port)
S7COMM_TEST_SERVER=127.0.0.1:1602 S7COMM_TEST_RACK=0 S7COMM_TEST_SLOT=1 \
S7COMM_TEST_DB=1 S7COMM_TEST_BIG_DB=9 zig build test-s7comm

# a real S7 client -> our responder
S7COMM_TEST_LISTEN=127.0.0.1:1702 zig build test-s7comm
```

The offline suite includes **113 byte-exact goldens captured from real traffic
between two independent third-party implementations** — every one of them
decodes and re-encodes to the identical octets, and every variable access is
rebuilt from its *decoded items* — plus full client↔responder round trips over
an in-memory wire and `std.testing.fuzz` sweeps over the TPKT decoder and
framer, the COTP decoder, the S7 decoder, the item and data-block decoders, the
request parameter decoder, the address parser and the responder's request
handler. For **S7CommPlus** it adds byte-pinned self-derived goldens, a
`rawshark`-confirmed envelope frame, and `std.testing.fuzz` sweeps over the
value walker, the VLQ decoders, the frame decoder, the object walker and the
path parser. See SPEC.md for what is third-party-validated versus self-derived,
and what is deferred.

Provenance: clean-room from the published ISO 8073 / RFC 1006 / S7comm frame
layouts, and — for S7CommPlus — from the documented / reverse-engineered
`s7comm-plus` wire layout (the Wireshark dissector's published field structure).
No third-party *source* was consulted as a design reference; a third-party stack
was used as a black-box test oracle and a live peer for classic S7comm, and
`rawshark` as a black-box envelope check for S7CommPlus. See SPEC.md and
`/NOTICE`.

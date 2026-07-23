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

## Verify

```
zig build test-s7comm                          # Debug
zig build test-s7comm -Doptimize=ReleaseFast
zig fmt --check modules/s7comm
```

118 tests, of which 116 are fully offline. The two live tests skip gracefully
(printing `SKIPPED:` and passing) when no peer is present:

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
handler. See SPEC.md for what is third-party-validated versus self-derived, and
what is deferred.

Provenance: clean-room from the published ISO 8073 / RFC 1006 / S7comm frame
layouts. No third-party source was consulted as a design reference; a
third-party stack was used as a black-box test oracle and as a live peer only.
See SPEC.md and `/NOTICE`.

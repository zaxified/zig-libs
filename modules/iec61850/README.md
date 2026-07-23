# iec61850

Pure-Zig **substation automation**: the IEC 61850 MMS stack an IED and a SCADA
client speak on TCP port 102, and **GOOSE**, the layer-2 multicast protocol
protection schemes trip breakers with. A typed, allocation-free codec for the
whole OSI sandwich (TPKT → COTP → session → presentation → ACSE → MMS), a
transport-agnostic client and server, the ACSI naming layer, report control
blocks, and **pure time-injected publisher and subscriber state machines** for
GOOSE. Sampled values (IEC 61850-9-2) come along for the ride.

- No pure-Zig IEC 61850 library exists; the field is C (`libiec61850`) and its
  bindings.
- **Platform:** any (codecs, state machines, the client's PDU logic and the
  responder are pure computation; only the optional `TcpTransport` adapter
  touches `std.Io.net`).
- **Model after:** ISO 9506 (MMS) as profiled by IEC 61850-8-1, over ISO
  8073/8327/8823/8650, with wire behaviour cross-checked against captured
  traffic between two independent third-party stacks, against the Wireshark
  `mms`/`goose`/`sv` dissectors, and by live round trips in both directions
  (see SPEC.md).

## Scope

### The MMS half

- **`ber`** (X.690) — the encoding every layer above TPKT uses, and the one
  GOOSE and SV use for their PDUs too. The **long-form tag escape** (MMS
  `FileOpen` is `[72]`, i.e. `bf 48`), the **long-form and indefinite length
  escapes**, and a **backwards writer** that emits definite lengths for nested
  structures with no second pass and no scratch allocation. Every descent is
  depth-budgeted, so an indefinite-length nest cannot overflow the stack.
- **`tpkt`** (RFC 1006 §6) — the four-octet shim whose length **counts the
  header itself**, plus a stream `Framer`.
- **`cotp`** (ISO 8073 / X.224 class 0) — `CR`/`CC` with the TSAPs and TPDU
  size, `DT` with its EOT bit, `DR`/`DC`/`ER`, and a `Reassembler`, because a
  real IED's variable list runs to several kilobytes.
- **`session`** (ISO 8327) — CONNECT/ACCEPT/ABORT and their nested PGI/PI
  parameter tree, the `LI == 255` 16-bit length escape, and the fact that data
  transfer is **two concatenated SPDUs** (`01 00 01 00`), not one.
- **`presentation`** (ISO 8823) — CP/CPA and the **presentation context
  definition list**: a `ContextTable` that matches the responder's result list
  **by position**, refuses a result list of the wrong length, and turns a PDU
  naming an undefined or rejected context into a typed error instead of a
  silently mis-dispatched PDU.
- **`acse`** (ISO 8650) — AARQ/AARE with the application context name and the
  AP/AE titles and qualifiers, RLRQ/RLRE, and ABRT. **`AARE.result != 0` means
  the association failed** even though the socket is healthy.
- **`mmsdata`** — the recursive `Data` CHOICE (array, structure, boolean,
  bit-string, integer, unsigned, floating-point, octet-string, visible-string,
  generalized-time, binary-time, bcd, booleanArray, objId, mMSString, utc-time)
  as a **zero-copy view with a hard depth bound**, plus `UtcTime` and
  `BinaryTime` with their impossible values range-checked.
- **`mms`** (ISO 9506-2) — `Initiate` (with the parameter CBB and
  service-supported bit strings), `Conclude`, `Identify`, `GetNameList` with
  continuation, `Read`/`Write` over named variables **and** named variable
  lists with the `AccessResult`/`DataAccessError` shapes,
  `GetVariableAccessAttributes` with a depth-bounded type tree,
  `GetNamedVariableListAttributes`, `DefineNamedVariableList`/
  `DeleteNamedVariableList`, `InformationReport`, and `FileOpen`/`FileRead`/
  `FileClose`/`FileDirectory`.
- **`acsi`** — the object-reference syntax in **both** forms:
  `LDName/LNName.DOName.DAName` and the `$`-separated MMS form
  `GGIO1$MX$AnIn1$mag$f`, with the functional constraint injected between the
  logical node and the data object. All 17 functional constraints
  (ST/MX/CO/SP/SV/CF/DC/SG/SE/EX/BR/RP/LG/GO/GS/MS/US). Malformed forms are
  typed errors, never a silently wrong name.
- **`report`** — buffered and unbuffered report control blocks, and the report
  they emit through an `InformationReport`: `OptFlds` decides which header
  fields are present and therefore **where every later field starts**, and the
  inclusion bit string decides how many data references, values and
  reason-for-inclusion codes follow.
- **`client`** — connect (all five nested handshakes, each checked on its own
  terms), read and write by ACSI reference, whole data sets, the three
  directory services with continuation, `Identify`, RCB read, enable, general
  interrogation and disable, and a report handler that is dispatched even when
  a report lands **in the middle of** a request/response exchange.
- **`server`** — a `Server`: the IED side as a pure function from one packet to
  one packet, backed by a caller-supplied table of named variables and data
  sets. Stand up one per simulated IED for fleet simulation.

### The GOOSE half

- **`goose`** — the Ethernet frame (destination multicast MAC, **optional
  802.1Q tag**, EtherType `0x88B8`, APPID, `Length`, two reserved fields) and
  the BER PDU (`gocbRef`, `timeAllowedtoLive`, `datSet`, `goID`, `t`, `stNum`,
  `sqNum`, `test`, `confRev`, `ndsCom`, `numDatSetEntries`, `allData`). The
  `Length` field counts from the APPID, so Ethernet padding is ignored rather
  than parsed; `numDatSetEntries` **must** agree with `allData`.
- **`publisher`** — the retransmission engine: on a state change `stNum`
  increments, `sqNum` resets, and the frame goes out immediately, then again on
  a **backoff ladder** (4, 8, 16 … up to a 1 s heartbeat), with
  `timeAllowedtoLive` **derived from the ladder** so it always exceeds the next
  expected retransmission.
- **`subscriber`** — the same machine on the receiving side, reporting four
  distinct typed events: a **`stNum` jump** (the data changed), an **`sqNum`
  gap** (frames were lost), a **TAL expiry** (the publisher is gone) and a
  **`confRev` mismatch** (the dataset was re-engineered and the values no
  longer mean what the configuration says). Plus test frames, `ndsCom`,
  out-of-order frames and recovery.
- Both are **pure and time-injected** — the caller passes `now_ms` into every
  entry point — so a whole event, a lost frame and a dead publisher are
  testable with no network at all.
- **`sv`** (IEC 61850-9-2) — the `0x88BA` frame and the `savPdu` with its
  `noASDU` count and `SEQUENCE OF ASDU`, including an explicit decoder for the
  9-2LE `{value, quality}` dataset.

Hostile input never panics anywhere: a truncated TPKT, a COTP length indicator
pointing past the buffer, a session parameter running off its group, a
presentation context list naming an undefined context, a BER length that
overruns, an indefinite length with no terminator, an `MMS Data` nested past
the depth bound, a GOOSE `Length` that disagrees with the frame, an `allData`
count contradicting the entries and a `UtcTime` with an impossible accuracy are
all typed errors.

## Use

```zig
const iec61850 = @import("iec61850");

// ── MMS client ──────────────────────────────────────────────────────────────
var tt = try iec61850.TcpTransport.connect(io, address); // or any Transport impl
defer tt.close();

var buf: [iec61850.client.min_buffer_size]u8 = undefined;
var ied = try iec61850.Client.init(tt.transport(), &buf, .{});
try ied.connect();
defer ied.disconnect();

// Read a measurement by ACSI reference + functional constraint.
const mag = try ied.readObject("substationLD/MMXU1.TotW.mag.f", .MX);
std.debug.print("{d}\n", .{try mag.asFloat()});

// Write a description.
var vbuf: [64]u8 = undefined;
var w = iec61850.ber.Writer.init(&vbuf);
try iec61850.Emit.visibleString(&w, "operator note");
try ied.writeObject("substationLD/GGIO1.NamPlt.vendor", .DC, w.done());

// Browse the model.
var names: [512][]const u8 = undefined;
const lds = try ied.getServerDirectory(&names);
const vars = try ied.getLogicalDeviceDirectory(names[0], &names);

// A whole data set in one request.
var it = try ied.readDataSet("substationLD/LLN0$Events");
while (try it.next()) |result| switch (result) {
    .success => |d| use(d),
    .failure => |e| report(e),
};

// Reporting: read the RCB, enable it, ask for a general interrogation, and
// receive what the IED pushes.
ied.setReportHandler(.{ .ctx = &my_state, .on_report = onReport });
const rcb = try ied.readRcb("substationLD/LLN0.EventsRCB01", .unbuffered);
try ied.enableReporting("substationLD/LLN0.EventsRCB01", .unbuffered,
    .{ .data_change = true, .general_interrogation = true }, 1000);
try ied.generalInterrogation("substationLD/LLN0.EventsRCB01", .unbuffered);
while (try ied.poll()) {}

// ── MMS server (fleet-simulation target) ────────────────────────────────────
var stval: [8]u8 = undefined;
var vars_table = [_]iec61850.Variable{
    .{ .domain = "ZIGLD", .item = "GGIO1$ST$Ind1$stVal", .storage = &stval, .len = len },
};
const domains = [_][]const u8{"ZIGLD"};
var ied_sim = iec61850.Server.init(.{}, .{ .variables = &vars_table, .domains = &domains });

var in: [16384]u8 = undefined;
var out: [32768]u8 = undefined;
while (true) {
    const n = try link.read(&in);
    const reply = (try ied_sim.handle(in[0..n], &out)) orelse break;
    try link.write(reply);
}

// ── GOOSE publisher ─────────────────────────────────────────────────────────
var pub_ = try iec61850.Publisher.init(.{
    .gocb_ref = "ZIGLD/LLN0$GO$gcbEvents",
    .dat_set  = "ZIGLD/LLN0$Events",
    .conf_rev = 1,
    .src      = my_mac,
    .appid    = 0x1001,
    .vlan     = .{ .priority = 4, .id = 100 },
}, .{}); // default ladder: 4, 8, 16 … 1000 ms

pub_.start(now_ms);
while (running) {
    if (breaker_changed) pub_.stateChange(now_ms);
    if (try pub_.tick(now_ms, &values, &frame_buf)) |frame| try l2.send(frame);
    sleepUntil(pub_.nextDeadline().?);
}

// ── GOOSE subscriber ────────────────────────────────────────────────────────
var sub = iec61850.Subscriber.init(.{
    .gocb_ref = "ZIGLD/LLN0$GO$gcbEvents",
    .expected_conf_rev = 1,
});
const f = try iec61850.GooseFrame.decode(raw_frame);
const pdu = try iec61850.GoosePdu.decode(f.pdu);
if (sub.matches(pdu)) for (sub.onFrame(pdu, now_ms).slice()) |ev| switch (ev) {
    .state_change     => |s| trip(s.st_num),
    .sequence_gap     => |g| countLoss(g),
    .conf_rev_mismatch => alarmReengineered(),
    else => {},
};
// And, on a timer, liveness:
if (sub.tick(now_ms)) |ev| alarmPublisherLost(ev);
```

The pure layers are usable on their own — `ber` for any BER, `tpkt.Framer` for
framing, `cotp.decode`, `session.decodeConnect`, `presentation.decodeCp`,
`acse.decodeAare`, `mms.decode`, `mmsdata.Data`, `acsi.parseAcsi`,
`goose.Frame`/`goose.Pdu` and `sv.SavPdu` — with your own I/O.

### Wiring GOOSE to a real NIC

This module opens **no raw socket**: `AF_PACKET` is a capability and platform
decision that does not belong in a codec. The `Link` seam takes whole Ethernet
frames, so the sibling `rawsock` module (or a pcap replay, or a netns bridge,
or a test double) plugs in behind two shim functions. There is **no dependency**
on `rawsock`; see the comment at the top of `src/transport.zig` for the exact
three lines.

## Safety

IEC 61850 MMS and GOOSE are **unauthenticated and unencrypted** by design.
Anyone with a path to TCP 102 can write a setpoint; anyone on the station bus
can forge a GOOSE frame with a higher `stNum` and it will win. This module
implements no IEC 62351 security; put transport security under it and read
SPEC.md, "Threat model", before pointing any of it at real equipment. The
`Server` is a **simulator, not an IED** — no control model, no access control,
no SCL.

## Verify

```
zig build test-iec61850                          # Debug
zig build test-iec61850 -Doptimize=ReleaseFast
zig fmt --check modules/iec61850
```

217 tests, of which 214 are fully offline. The three live tests skip gracefully
(printing `SKIPPED:` and passing) when no peer is present:

```
# our client -> a real IEC 61850 server
IEC61850_TEST_SERVER=127.0.0.1:102 IEC61850_TEST_LD=simpleIOGenericIO \
  zig build test-iec61850

# a real IEC 61850 client -> our server (serves N peers in sequence)
IEC61850_TEST_LISTEN=127.0.0.1:10102 IEC61850_TEST_PEERS=3 \
  zig build test-iec61850

# real GOOSE frames (one hex frame per line) through the subscriber
IEC61850_TEST_GOOSE_HEX=./goose.hex zig build test-iec61850
```

The offline suite includes **82 byte-exact MMS goldens captured from real
traffic between two independent third-party implementations**, plus real
captured GOOSE and SV frames — every one of them decodes, and every one this
module has an encoder for **re-encodes to the identical octets from its decoded
fields**, including the entire 187-octet association handshake rebuilt from
scratch. On top of that: full client↔server round trips over an in-memory wire,
a publisher↔subscriber round trip with an injected clock and a deliberately
dropped frame, and 16 `std.testing.fuzz` sweeps. See SPEC.md for what is
third-party-validated versus self-derived, and what is deferred.

Provenance: clean-room from the published ISO 8073 / RFC 1006 / ISO 8327 / ISO
8823 / ISO 8650 / ISO 9506 / IEC 61850-8-1 layouts. No third-party source was
consulted as a design reference; a third-party stack was built and run as a
black-box test oracle and as a live peer only. See SPEC.md and `/NOTICE`.

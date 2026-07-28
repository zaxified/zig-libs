# iec61850

Pure-Zig **substation automation**: the IEC 61850 MMS stack an IED and a SCADA
client speak on TCP port 102, and **GOOSE**, the layer-2 multicast protocol
protection schemes trip breakers with. A typed, allocation-free codec for the
whole OSI sandwich (TPKT → COTP → session → presentation → ACSE → MMS), a
transport-agnostic client and server, the ACSI naming layer, a **server-side
reporting engine** (BRCB and URCB, `TrgOps`, `BufTm` coalescing, integrity and
general interrogation), **logging** with the MMS journal services, **setting
groups**, the **control model** that actually operates a breaker, an **SCL
parser, type resolver and writer**, and **pure time-injected publisher and
subscriber state machines** for GOOSE. Sampled values (IEC 61850-9-2) come along
for the ride.

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
  (ST/MX/CO/SP/SV/CF/DC/SG/SE/EX/BR/RP/LG/GO/GS/MS/US); `scl.Fc` adds edition
  2's `OR`/`BL` and 2.1's `SR` on top for SCL parsing. Malformed forms are typed
  errors, never a silently wrong name.
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
- **`control`** (IEC 61850-7-2 §20) — the part that operates plant rather than
  reading it. All four `ctlModel`s (direct/sbo × normal/enhanced),
  `Oper`/`SBO`/`SBOw`/`Cancel` with `ctlVal`, `operTm`, `origin`, `ctlNum`, `T`,
  `Test` and `Check`; the 28-value **`AddCause`** enumeration and the
  **`LastApplError`** structure that carries it, which is the difference between
  "it failed" and "the synchrocheck refused"; and **`CommandTermination`**,
  which under the enhanced models arrives *after* the write response as an
  unsolicited `InformationReport` — so a client that stops at the write reports
  a trip that never happened. Two state machines, both **pure and
  time-injected**: `Machine` on the client side (select → operate →
  termination, `sboTimeout`, the `ctlNum` matching rule, `Cancel` at any point)
  and `Point` on the server side (arms and expires selects, enforces
  ownership and the interlocks, owes the terminations).
- **`scl`** (IEC 61850-6) — the configuration language, parsed with the `xml`
  sibling: `Header`, `Communication` (`SubNetwork`/`ConnectedAP` with the IP,
  OSI, MAC, APPID and VLAN parameters, and the `GSE`/`SMV` addresses that live
  there rather than next to their control blocks), the
  `IED → AccessPoint → Server → LDevice → LN0/LN → DOI/DAI` tree, `DataSet`s
  with their `FCDA`s, `ReportControl`/`GSEControl`/`LogControl`/`SettingControl`,
  and `DataTypeTemplates`. **`resolve` walks the type graph** —
  `LN → LNodeType → DOType → DAType → DAType…` — and produces the flat list of
  MMS names the wire uses, with cycle detection, a depth bound and typed errors
  for every way the graph can lie. This is the only file here that allocates.
- **`sclwrite`** — the other direction: serialises a model back to an `ICD`/`CID`
  document. Optional attributes are written **only when they differ from the
  schema default** and the source's own namespace is kept, because a reader
  decides which edition's defaults to apply from that URI. A cyclic type graph is
  refused before an octet is written. The test that backs it is a round trip
  through the resolver: parse → emit → parse → **identical name space**.
- **`reporting`** — the **server side** of IEC 61850-7-2 §17. Live report control
  blocks: `RptID`, `RptEna`, `Resv`/`ResvTms`, `DatSet`, `ConfRev`, `OptFlds`,
  `BufTm`, `SqNum`, `TrgOps`, `IntgPd`, `GI`, and for a BRCB `PurgeBuf`,
  `EntryID` and `TimeOfEntry`. Data-change / quality-change / data-update /
  integrity / general-interrogation triggers each produce the right per-member
  `ReasonCode`; `BufTm` **coalesces** a burst into one report instead of a storm;
  and a BRCB **retains** what happened while no client was listening, resuming
  from the client's `EntryID` and raising `BufOvfl` when its bounded, caller-owned
  buffer wraps over something undelivered. A report larger than the negotiated
  PDU is **segmented** — `SubSeqNum`, `MoreSegmentsFollow` and a per-segment
  inclusion bit string, with one `SqNum` and one `EntryID` across the set —
  and `report.Reassembler` is the client-side half that puts one back together.
  A client may **re-bind `DatSet`** at runtime, which re-resolves the data set
  and bumps `ConfRev`, and is refused while `RptEna` is set. `Resv` (URCB),
  `ResvTms` (BRCB, including the timed reservation that outlives the
  association) and `Owner` arbitrate **two clients contending for one block**.
  Pure and time-injected: `BufTm`, `IntgPd` and a reservation lifetime expire
  because the caller calls `tick`.
- **`logging`** — IEC 61850-7-2 §18. The `LCB` (`LogEna`, `LogRef`, `DatSet`,
  `OldEntrTm`, `NewEntrTm`, `OldEntr`, `NewEntr`, `TrgOps`, `IntgPd`), a bounded
  circular log over caller-owned storage, and the MMS journal services
  `ReadJournal` (with `listOfVariables` filtering), `GetJournalStatus`,
  `InitializeJournal` (deleting entries by time or `EntryID`) and
  `DeleteJournal` in both directions.
- **`settinggroups`** — IEC 61850-7-2 §19. `SelectActiveSG`, `SelectEditSG`,
  `SetEditSGValue`, `ConfirmEditSGValues` and `GetSGValues` over the `SGCB` and
  the `SE`/`SG` functional constraints. **An uncommitted edit is invisible**:
  writing `SE` changes the edit buffer, `SG` still reads the active group, and a
  confirm with no preceding edit is refused rather than committing an empty
  buffer over a live relay setting. `ResvTms` bounds an **abandoned** edit: a
  selection that goes quiet for that many seconds is taken back on `tick`, so a
  client that vanishes without dropping its association cannot hold the setting
  groups for ever.
- **`server`** — a `Server`: the IED side as a pure function from one packet to
  one packet, backed by a caller-supplied table of named variables, data sets,
  **control objects, report control blocks, logs and setting groups**. It
  enforces the control model, arms and expires selects, emits
  `CommandTermination`/`LastApplError`, and pushes reports out of
  `pendingNotification`. Stand up one per simulated IED for fleet simulation.

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

// ── operating a breaker (IEC 61850-7-2 §20) ─────────────────────────────────
const ref = "substationLD/CSWI1.Pos";

// 1. Ask the IED what it expects. Everything below follows from ctlModel.
const ctl_model = try ied.readCtlModel(ref);
const sbo_timeout = (try ied.readSboTimeout(ref)) orelse 30_000;

// 2. Drive the whole command: select if needed, operate, and — under an
//    enhanced model — WAIT for the CommandTermination, which is the only thing
//    that says the breaker actually moved.
ied.setControlHandler(.{ .ctx = &my_state, .on_notification = onControl });

var value: [8]u8 = undefined;
var vw = iec61850.ber.Writer.init(&value);
try iec61850.Emit.boolean(&vw, true); // close

var machine = iec61850.control.Machine.init(ctl_model, sbo_timeout);
ied.executeControl(&machine, ref, .{
    .ctl_val = vw.done(),
    .origin  = .{ .or_cat = .station_control, .or_ident = "scada-1" },
    .t       = iec61850.UtcTime.fromMillis(now_ms, 10),
}, now_ms) catch |e| switch (e) {
    error.ControlRejected => {
        // Not "it failed" — *why* it failed.
        const f = machine.failure.?;
        log("{s} refused at {s}: {s}", .{ ref, @tagName(f.stage),
            if (f.add_cause) |a| a.name() else "(no AddCause)" });
        if (f.add_cause) |a| if (a.transient()) scheduleRetry();
    },
    else => return e,
};

// ── SCL: address a substation without being told every reference ────────────
var doc = try iec61850.scl.parse(gpa, cid_bytes, .{});
defer doc.deinit();
var model = try iec61850.scl.resolve(&doc, gpa, "MyIED");
defer model.deinit();

for (model.nodes) |n| if (n.leaf) {
    // n.domain / n.item is exactly what GetNameList returns, e.g.
    // "substationLD" / "GGIO1$CO$SPCSO4$SBOw$origin$orCat"
};

// The control model comes out of the file too, so no round trip is needed.
const from_file = model.ctlModel("substationLD", "CSWI1$CO$Pos").?;

// A GOOSE subscriber configured from the SCD rather than hand-wired.
const ln0 = doc.ied("MyIED").?.access_points[0].devices[0].lns[0];
const gcb = ln0.gse_controls[0];
const addr = doc.cbAddress("MyIED", "substationLD", gcb.name).?;
var ref_buf: [128]u8 = undefined;
var sub_from_scl = iec61850.Subscriber.init(.{
    .gocb_ref = try iec61850.scl.controlBlockRef("substationLD", "LLN0", .GO, gcb.name, &ref_buf),
    .expected_conf_rev = gcb.conf_rev,
});
_ = addr.address.appId(); // and the APPID/MAC/VLAN to bind the NIC filter with

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
`Server` is a **simulator, not an IED**: it enforces the control model and it
now reports, logs and switches setting groups, but it has no access control and
no file system.

**Writing under `CO` operates plant.** The control model is here so that a
client applies the interlocks a real one applies — the select, the `ctlNum`, the
`Check` bits, the `AddCause` — rather than writing `Oper` by hand. Nothing stops
a caller writing by hand; `FunctionalConstraint.isOperational` names the five
constraints under which a write changes what the plant does.

## Verify

```
zig build test-iec61850                          # Debug
zig build test-iec61850 -Doptimize=ReleaseFast
zig fmt --check modules/iec61850
```

The suite runs fully offline except for the live tests below, which skip
gracefully (printing `SKIPPED:` and passing) when no peer is present:

```
# our client -> a real IEC 61850 server
IEC61850_TEST_SERVER=127.0.0.1:102 IEC61850_TEST_LD=simpleIOGenericIO \
  zig build test-iec61850

# our client OPERATING a real IED, through every control model
IEC61850_TEST_CONTROL=127.0.0.1:102 zig build test-iec61850

# an SCL file resolved and compared against the IED it configures, name for name
IEC61850_TEST_SCL_FILE=./model.cid IEC61850_TEST_SCL_SERVER=127.0.0.1:102 \
  zig build test-iec61850

# a real IEC 61850 client -> our server (serves N peers in sequence)
IEC61850_TEST_LISTEN=127.0.0.1:10102 IEC61850_TEST_PEERS=3 \
  zig build test-iec61850

# a real IEC 61850 CONTROL client -> our server's control objects
IEC61850_TEST_LISTEN_CONTROL=127.0.0.1:102 zig build test-iec61850

# a real IEC 61850 REPORTING or LOG client -> our server (RCBs, a log, an SGCB)
IEC61850_TEST_LISTEN_REPORT=127.0.0.1:10102 IEC61850_TEST_PEERS=3 \
  zig build test-iec61850

# a real client reassembling a SEGMENTED report (a data set wider than one PDU)
IEC61850_TEST_LISTEN_SEGMENT=127.0.0.1:102 zig build test-iec61850

# TWO real clients contending for one RCB: Resv, Owner and the refusal
IEC61850_TEST_LISTEN_RESV=127.0.0.1:102 IEC61850_TEST_PEERS=3 \
  zig build test-iec61850

# an SCL file through parse -> emit -> parse, name space compared
IEC61850_TEST_SCL_FILE=./ied.icd IEC61850_TEST_SCL_OUT=/tmp/out.icd \
  zig build test-iec61850

# real GOOSE frames (one hex frame per line) through the subscriber
IEC61850_TEST_GOOSE_HEX=./goose.hex zig build test-iec61850
```

The offline suite includes **82 byte-exact MMS goldens plus 15 control-model
goldens captured from real traffic between two independent third-party
implementations**, plus real captured GOOSE and SV frames — every one of them
decodes, and every one this module has an encoder for **re-encodes to the
identical octets from its decoded fields**, including the entire 187-octet
association handshake rebuilt from scratch and the `TypeSpecification` of a
select-before-operate control object rebuilt octet for octet from this module's
own model. On top of that: full client↔server round trips over an in-memory wire
covering all four control models, a publisher↔subscriber round trip with an
injected clock and a deliberately dropped frame, and `std.testing.fuzz`
sweeps over every decoder. See SPEC.md for what is third-party-validated versus self-derived, and
what is deferred.

The SCL resolver was checked against **twelve different configuration files**
by standing up the IED each one configures and comparing the resolved name
space against its own `GetNameList`, in both directions: **3,273 names, every
one matched, none missing and none invented**.

The **reporting engine** is driven by third-party clients rather than only by
its own tests: a reference stack's reporting and log example clients were
pointed at this server and observed to receive data-change, integrity and
general-interrogation reports with the right per-member reason codes, to read
the URCB and the fourteen-member BRCB, and to read a log back over
`ReadJournal`. **Segmentation and reservation are driven the same way**: a
reference client subscribing to a data set wider than the negotiated PDU
received a report split into two `InformationReport`s and printed every one of
its twelve members with the right reference and reason; and **two** reference
clients pointed at one report control block resolved as they should — the first
took `Resv` and became `Owner`, the second's write came back
`object-access-denied` and its own stack reported the failure, while a third
association read the twelve-member URCB structure and saw `Resv = true` and
`Owner = c0a80101`. The **SCL writer** was checked by emitting 44 real
configuration files and re-resolving each emission to the identical name space,
and by feeding every emission to a third-party SCL model generator — none
rejected, and **36 of the 44 produce a byte-identical generated model**. See
SPEC.md for exactly what ran in which direction.

Provenance: clean-room from the published ISO 8073 / RFC 1006 / ISO 8327 / ISO
8823 / ISO 8650 / ISO 9506 / IEC 61850-8-1 layouts. No third-party source was
consulted as a design reference; a third-party stack was built and run as a
black-box test oracle and as a live peer only. See SPEC.md and `/NOTICE`.

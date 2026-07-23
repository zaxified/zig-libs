# iec61850 — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

Two stacks sharing one BER codec. Every wire struct uses explicit shifts in its encode/decode
rather than a `packed struct`, so the octet layout never depends on Zig's bitfield-packing rules,
and nothing anywhere allocates.

### The BER codec, which everything else is only as correct as

- **Three escapes, all exercised by real traffic.** The **long-form tag** (`0x1F` in the identifier,
  then base-128 continuation octets) is not exotic here: MMS `FileOpen` is `[72]` = `bf 48` and
  `FileDirectory` is `[77]` = `bf 4d`, and a decoder that stops at `bf` reads the next octet as a
  length. The **long-form length** (`0x81`..`0x84`) appears in every reply over 127 octets and the
  two-octet form in the 6675-octet `GetNameList` the captured IED sent. The **indefinite length**
  (`0x80`, terminated by `00 00`) is legal BER and is decoded, but it is only findable by parsing
  the nested elements — which is unbounded recursion unless it is budgeted. Every entry point
  therefore carries a depth budget and returns `error.TooDeep`; a 512-deep `a0 80 …` nest is a test.
- **Encoding runs backwards.** Content first, header prepended once its length is known. That is
  the only way to emit definite lengths for a deeply nested structure without a second pass or a
  scratch buffer, and it is what lets the client wrap an MMS PDU in presentation + session + COTP +
  TPKT **in one buffer with the PDU copied exactly once** — all four of those layers are prefixes.
- **Non-minimal integers are refused.** Nine redundant leading sign bits (`00 01`, `ff ff`) are a
  typed error, not a lenient parse. A permissive integer decoder is a malleability hazard in any
  protocol that ever hashes a re-encoding, and MMS is one BER dialect away from several that do.
- **`Writer.boolean` emits `0x01`, not DER's `0xFF`.** Every IEC 61850 stack observed here writes
  `0x01`, and matching the wire is what makes the goldens byte-exact; the decoder accepts both.

### The OSI sandwich

- **`tpkt`.** The length field counts **the header itself**. A decoder that reads it as a payload
  length desynchronises by four octets and never recovers, and TPKT is the only framing MMS has.
- **`cotp`.** `LI` counts the octets after itself excluding user data, which is what fixes `LI == 2`
  for a class-0 `DT`; a different value is refused rather than guessed at. The variable part is kept
  **raw** alongside the parsed parameters, so a CR/CC re-encodes verbatim whatever order the peer
  used. `Reassembler` exists because a real IED's variable list is 6675 octets and class 0 segments;
  a peer that never sets EOT can fill the caller's buffer and then errors, never grow it.
- **`session`.** Data transfer is **two concatenated SPDUs** — GIVE TOKENS (SI 1, LI 0) then DATA
  TRANSFER (SI 1, LI 0), i.e. the four octets `01 00 01 00` in front of every presentation PDU. An
  implementation that emits one of them wedges a real peer. `LI == 255` is an **escape** to a 16-bit
  length, not a length; any parameter over 254 octets uses it, and a 600-octet CP is a test.
- **`presentation` — the layer implementations get wrong.** The context definition list is a
  negotiation: the initiator proposes `{id, abstract syntax OID, transfer syntaxes}` triples and the
  responder answers with a **positionally matched** result list. Everything after that names a
  context **by id only**. So `ContextTable` is connection state, not two hard-coded constants:
  `applyResults` refuses a result list whose length differs from the proposal rather than zipping
  short, a PDV naming an id that was never defined is `error.UndefinedContext`, and one naming a
  context the responder *rejected* is a **separate** `error.RejectedContext`, because they are
  different bugs. The table is fixed-size, so a peer proposing a thousand contexts gets
  `error.TooManyContexts` and not a heap.
- **`acse`.** `AARE.result != 0` means the association failed even though TCP is up and the
  presentation layer accepted its contexts — the failure mode a naive client reports as "connected".
  `user-information` is an `EXTERNAL`; the captured stack uses the **indirect reference** (the
  presentation context id) rather than a direct-reference OID, and both forms decode.

### MMS and IEC 61850

- **The invoke id is the only correlation there is.** `Initiate` negotiates several outstanding
  confirmed requests and a response carries nothing else to say which request it answers. `exchange`
  therefore loops on the id and **skips anything else**, which is also what makes an
  `InformationReport` arriving between a request and its response harmless rather than fatal.
- **`AccessResult` overlaps `Data` deliberately.** `failure [0] IMPLICIT DataAccessError` and the
  `Data` alternatives `[1]..[17]` share one context namespace, legal exactly because `Data` has no
  `[0]`. A decoder that assumes every access result is a value silently reports whatever
  `DataAccessError` happens to look like, so `AccessResultIterator` branches on `[0]` first.
- **`Read` and `Write` order their fields differently, and a write has two `[0]`s in a row.** A read
  is `{ specificationWithResult [0], variableAccessSpecification [1] }`; a write is
  `{ variableAccessSpecification, listOfData [0] }` where the access specification's own
  `listOfVariable` is *also* `[0]`. `decodeWriteRequest` therefore decides by **position**, not tag.
- **`Data` is a view, never a tree**, and `validate` is the only recursive function — one walk
  against a depth bound of 16, after which every accessor is flat. `utc-time` and `binary-time` are
  the two encodings that hide an impossible value behind a fixed width, so both are range-checked:
  a `TimeAccuracy` of 25..30 is undefined and is a decode error, because a subscriber that treats an
  undefined accuracy as "accurate" trusts a timestamp it should not.
- **`acsi`: the functional constraint is metadata in one form and a path component in the other.**
  `LD/GGIO1.AnIn1.mag.f` + `MX` becomes the MMS item id `GGIO1$MX$AnIn1$mag$f` — the FC injected
  **between** the logical node and the data object. A naive `s/./$/g` produces a name the IED
  reports as non-existent, and reading `stVal` under `MX` instead of `ST` is not an error the
  protocol reports: the object simply is not there.
- **`report`: `OptFlds` decides where every later field starts.** A report is a positional list of
  `Data` values whose shape a bit string selects, and because the values are just `Data`, a wrong
  offset does not fail — it reports the sequence number as a measurement. The two "one per included
  entry" runs (data references, reason codes) are counted from the **inclusion bit string**, not
  from the data set's size, which is what makes a partial report decodable at all.
- **`client.enableReporting` writes `TrgOps` and `IntgPd` *before* `RptEna`.** An IED refuses a
  configuration write while the RCB is enabled; the order is the single most common reporting bug.
- **`server.store` validates before it stores.** A written value must decode as a well-formed,
  depth-bounded `Data` and fit the variable's storage, or it is a per-object `DataAccessError` —
  never a partial write.

### The control model

- **The write response is not the answer.** Under `direct-with-enhanced-security`
  and `sbo-with-enhanced-security` a positive `Write` response to `Oper` means
  only "accepted for execution"; whether the breaker moved arrives later and
  **unsolicited**, as a `CommandTermination` — an `InformationReport` naming the
  control object with its `Oper` value echoed. A client that stops at the write
  response reports a trip that never happened, which is why `Machine` has an
  `awaiting_termination` state and `executeControl` will not return until it
  leaves it.
- **The negative termination carries two variables.** `CommandTermination-` is
  one `InformationReport` whose `listOfVariable` holds **`LastApplError` first**
  and the control object second, with two matching access results. A decoder
  that assumes one value per report reads the `LastApplError` structure as the
  echoed command. `control.classify` walks the pair, which is also what tells a
  control notification apart from an ordinary `RPT` report — they share the
  `InformationReport` channel and are not distinguishable by service tag.
- **`AddCause` is refused when it is out of range**, like every other
  enumeration here. A vendor value outside 0..27 is `error.UnknownAddCause`
  rather than a number a caller might `switch` on and mis-handle.
- **`Command` recovers `operTm` and `Check` by shape, not by assumption.** The
  structure is `{ ctlVal, [operTm,] origin, ctlNum, T, Test, [Check] }`, and
  which optionals are present depends on the object's `DAType` — the
  `…Operate_5` templates have `operTm`, `Cancel` has no `Check`. Member 1 is
  `operTm` when it is a `utc-time` and `origin` when it is a `structure`; a
  trailing `bit-string` is `Check`. No other member can take those alternatives,
  so the recovery is unambiguous, and `check == null` is kept distinct from
  `check == .{}` so a caller cannot mistake "Cancel has no Check" for "no
  overrides requested".
- **`ctlVal` is a raw encoded `Data` TLV**, because its type comes from the
  common data class: `BOOLEAN` for an SPC, a two-bit `Dbpos` for a DPC, `INT32`
  for an INC, a float for an APC. Typing it as `bool` would model one CDC.
- **The two state machines are pure and time-injected**, like the GOOSE ones.
  `Machine.tick` is the only place time enters the client side and `Point.tick`
  the only place it enters the server side; `sboTimeout` expires because the
  caller keeps calling, never because this module owns a timer. `Point.tick`
  resets the object, so the `ctlNum` a termination must echo is read *before*
  it runs — a bug found by a test that expected the echo to match.
- **`ctlNum` matching is a correctness requirement, not a nicety.** An IED
  serving several clients terminates each one's command separately; a client
  that ignores the number reports another client's success as its own.
  `Machine.terminated` returns `error.CtlNumMismatch` and stays waiting.
- **The `Check` bits are an override, not a request.** Setting `synchrocheck` or
  `interlock-check` asks the IED to *skip* a safety check. `Point` honours them
  only when `allow_check_override` is set, because whether an override is
  permitted is the IED's decision and not the client's.
- **`Test` must not move the plant.** `Server.applyControlValue` returns without
  touching `stVal` for a test command; that distinction is the whole reason the
  flag is on the wire.
- **A responder that cannot describe its control objects cannot be operated.**
  A real control client calls `GetVariableAccessAttributes` on `LN$CO$DO`
  *before* it writes anything and treats a failure as "no such object" — a
  third-party client did exactly that against this server and reported all four
  objects missing until the service was implemented. `Point.emitTypeSpec` builds
  the `TypeSpecification` from `ctlModel`, and its output for a
  select-before-operate object is **byte-identical** to the one a real IED sent.

### SCL

- **The functional constraint lives on the `DA`, not on the `DO`**, and it
  applies to the whole subtree below it. A data object therefore appears under
  *every* constraint any of its attributes carries, with different children each
  time: `Mod` is under `ST` (its `q`, `t`) **and** under `CF` (its `ctlModel`).
  A resolver that hangs the FC off the data object produces names the IED
  reports as non-existent.
- **Cycles are caught on the path, not by the depth budget alone.** A `DAType`
  that reaches itself in two steps would otherwise emit twelve levels of
  plausible-looking names before the budget noticed. `ResolveCtx.path` holds the
  `DAType` ids currently being expanded and `error.CyclicType` fires on the
  second visit; the budget still catches an `SDO` cycle, which is bounded by
  `DOType`s instead.
- **Control blocks are part of the name space.** A `ReportControl` with
  `<RptEnabled max="2"/>` is `…RCB01` *and* `…RCB02`, each with its eleven URCB
  attributes — a client that writes to the bare name finds nothing there. A
  `GSEControl` is `LLN0$GO$<name>` with a `DstAddress` **structure**, a
  `LogControl` is `LLN0$LG$<name>`, and a `SettingControl` is `LLN0$SP$SGCB`.
  The exact attribute lists vary by edition and by implementation, so the BRCB
  and SGCB lists are `Options` fields rather than constants (IEC 61850-8-1
  spells the buffered timestamp `TimeOfEntry`; at least one widely deployed
  stack spells it `TimeofEntry`, and `ResvTms` is present on some IEDs and not
  others).
- **`SE` is mirrored into `SG` when the device has a setting-group control
  block** (IEC 61850-7-2 §12): the editable copy and the active group's value
  are two halves of one name space, and an SCL that declares only `SE` still
  yields both. A resolver that takes the file literally misses every `SG` name.
- **An array is one MMS variable.** A `DA`/`SDO` with `count` is a single name;
  its elements are reached with the alternate-access sub-specification, never
  with more `$` components. Flattening `phsAHar[0..15]` into sixteen names
  invents fifteen objects the IED does not serve, and an `FCDA` naming
  `phsAHar(9).cVal` resolves to the array, not past it.
- **`PhyComAddr` is a composite basic type**, not a leaf: the MMS mapping
  expands it into `Addr`/`PRIORITY`/`VID`/`APPID`. A GOOSE control block's
  `DstAddress` is one, and so is any `DA` declared `bType="PhyComAddr"`.
- **The GOOSE and SV addresses live in `Communication`, not next to their
  control blocks.** `SubNetwork → ConnectedAP → GSE/SMV` carries the MAC, APPID
  and VLAN a subscriber must bind with; `GSEControl` carries only the data set
  and `confRev`. Nothing in the `IED` section says which MAC a control block
  publishes on.
- **`Val` is checked against `bType`.** A `BOOLEAN` that says `"maybe"`, an
  `INT8U` that says `"400"`, a `VisString32` of forty characters and an `Enum`
  value that is not in its `EnumType` are configuration errors that would
  otherwise surface as a type mismatch on the wire long after commissioning.
- **This is the only file here that allocates**, and it says so: an SCL document
  is a graph of unbounded shape and the `xml` sibling hands back an allocated
  tree. Everything is arena-backed and freed by one `deinit`. The parser
  underneath is XXE- and billion-laughs-proof and rejects `DOCTYPE` by default;
  SCL has no legitimate use for either. The one default this module overrides is
  `id_attr_names`, which it empties — SCL's `id` is a *type identifier*, not an
  XML ID, and treating it as one makes real files fail with `DuplicateId`.

### GOOSE

- **`Length` counts from the APPID field**, i.e. eight header octets plus the PDU. Ethernet pads
  short frames to 60 octets, so `Length` is the *only* way to know where the PDU ends; a decoder
  that trusts the captured frame length reads padding as BER. The optional 802.1Q tag shifts
  everything by four octets, and a subscriber that assumes the EtherType is at offset 12 misparses
  every tagged publisher — which in a real substation is all of them.
- **`numDatSetEntries` must agree with `allData`.** GOOSE has no integrity protection whatsoever, so
  the redundant count is the only consistency signal there is; the encoder derives it from the
  values it is given and never from a caller field, so the two cannot disagree on the wire.
- **The retransmission ladder, and why `timeAllowedtoLive` is derived from it.** Reliability is
  bought entirely with repetition: steady-state heartbeat, then on a state change `stNum` increments,
  `sqNum` resets, and the frame goes out immediately and again at 4, 8, 16 … ms until the heartbeat
  is reached. TAL is `2 × the next interval` (floored at 10 ms), because a **constant** TAL is either
  too short during the fast burst — spurious "publisher lost" alarms — or too long in steady state,
  where a dead publisher goes unnoticed for seconds. A test asserts `tal > next_interval` at every
  rung, and the round-trip test polls the subscriber at exactly the next transmission deadline and
  requires it not to have declared the publisher dead.
- **The subscriber distinguishes four conditions that a naive one conflates.** A `stNum` jump is a
  data change and **resets the sequence expectation** (so 5 → 0 is not a gap); an `sqNum` gap is
  loss, and the newer frame still wins; a TAL expiry fires **exactly once per outage** and clears
  `dataUsable`; a `confRev` mismatch means the dataset was re-engineered and the values no longer
  mean what the configuration says — the dangerous case, because nothing looks wrong. Several can be
  true of one frame, so `onFrame` returns a bounded **set**. `sqNum` comparison is wrapping
  (`seqAfter`), because a `u32` at burst rates genuinely rolls over.
- **`stNum` never wraps to 0**, which is reserved.

Concurrency: `.single_owner` — one `Client`/`Server` owns one association's buffers and invoke ids;
one `Publisher`/`Subscriber` owns one control block's counters. Nothing is shared or global, and the
clock and any threading are the caller's.

Error policy: every decode entry point returns a typed error on malformed input. Nothing panics,
allocates or loops unboundedly — **except `scl`**, which allocates by construction and says so at
the top of the file; it is arena-backed, and every other file in this module remains
allocation-free.

## Verification

### What is third-party-validated

The strongest evidence here is not a hand-written vector — it is **real traffic between two
independent implementations that are not this module**, **live round trips in both directions**, and
**an independent dissector reading this module's own output**.

**Oracle used:** `libiec61850` 1.6.1 (Michael Zillgith / MZ Automation, GPL-3.0 / commercial dual).
It was cloned and built with `cmake` and used **as a black box only** — its example server and its
example client binaries were executed, the octets that crossed the wire were recorded, and it acted
as a live peer in both directions.

> **Licence hygiene, stated explicitly.** libiec61850 is GPL-3.0. **No source file of it was
> opened.** What was read was: the CMake build output, the file listing produced by `ls`, the usage
> text `file-tool` and `mms_utility` print, the console output of its example clients and servers,
> and — new in the SCL work — **the `.icd`/`.cid` configuration files it ships**. Those are
> configuration *data*, not source: XML documents in a published IEC standard's own schema, read
> only as parser input and as the subject of a name-space comparison, with none of their content
> copied into this repository except the object names that also appear in the captured wire traffic
> (`simpleIOGenericIO`, `GGIO1`, `SPCSO1`…). Under CONVENTIONS §5 running an installed third-party
> binary purely as a black-box compatibility oracle, and feeding its data files to a parser, is
> neither required attribution nor a design reference, so this needs **no `/NOTICE` entry** — the
> same status as diffing against `tar` or `nft`. Every ASN.1 layout in this module was derived from
> the published ISO/IEC specifications and then *confirmed* against captured octets, never the other
> way round; the same is true of every SCL element, which came from IEC 61850-6's own schema.

**Wireshark 4.6.4** (`rawshark`; `tshark` is not installed and cannot be without root) was used as a
second, fully independent decoder.

Concretely:

1. **82 byte-exact captured MMS goldens** (`goldens.zig`). A `libiec61850` example client was pointed
   at a `libiec61850` example server through a TPKT-aware recording TCP proxy inside a network
   namespace (`unshare -rn`, which grants `CAP_NET_BIND_SERVICE` for the privileged port 102), and
   every packet that crossed the wire was logged as hex. Four assertions run over the whole table:
   - every frame decodes — TPKT, COTP, session, presentation (against a negotiated context table)
     and MMS;
   - every frame **re-encodes to the identical octets** wherever this module has an encoder, built
     from the *decoded fields*: a read request from its decoded object names **and its alternate-access
     sub-specification**, a write request from its decoded names and raw values, a `GetNameList`
     request and response, a write response, an `InformationReport` from its decoded access results,
     the `Initiate` request and response, the COTP CR/CC, the file services and the
     `confirmed-ErrorPDU`;
   - **the entire association handshake is reproduced from scratch** — the COTP CR and the
     187-octet packet carrying session CONNECT / presentation CP / ACSE AARQ / MMS Initiate, built
     from this module's own defaults and compared byte for byte against the captured packet;
   - a coverage assertion fails if the table stops containing a COTP CR and CC, a session CONNECT,
     ACCEPT and ABORT, a read of a variable and of a variable list, a single and a **three-variable**
     write, `GetNameList` at domain / named-variable / named-variable-list scope,
     `GetNamedVariableListAttributes`, `GetVariableAccessAttributes`, an `InformationReport`, a
     `confirmed-ErrorPDU`, a file service, an `AccessResult` **failure**, a floating-point value and
     a structure value.

   Coverage highlights: the **6675-octet** `GetNameList` reply listing a real IED's 304 named
   variables, which is the only frame needing BER's two-octet length form; the `bf 4d`/`bf 48`
   long-form service tags; a write of `TrgOps`, `IntgPd` and `RptEna` in one PDU; seven consecutive
   `InformationReport`s showing the reason-for-inclusion changing from general-interrogation to
   integrity; and a session ABORT carrying a presentation ARU carrying an ACSE `ABRT`.

2. **Real captured GOOSE and SV frames** (`goose.zig`, `sv.zig`). `libiec61850`'s
   `goose_publisher_example` and `sv_publisher_example` were run onto a **veth pair inside a network
   namespace** and captured with an `AF_PACKET` sniffer. Two GOOSE frames (`sqNum` 0 and 3, with the
   data set gaining a fourth entry and the `Length` field tracking it) and one two-ASDU SV frame are
   pinned; each decodes, and each **re-encodes to the identical octets from its decoded values**.

3. **Wireshark cross-check — `rawshark`, field by field, in both directions.** The captured frames
   and this module's *own output* were written to pcap and dissected with the Wireshark
   `tpkt`/`cotp`/`ses`/`pres`/`acse`/`mms`, `goose` and `sv` dissectors:
   - *captured MMS*: `pres.presentation_context_identifier` = 1, 3, 1 on the CP; `acse.result` = 0
     on the AARE; `mms.confirmedServiceRequest` = 4/5/1 matching read/write/getNameList;
     `mms.invokeID` matching; `mms.domainId` = `simpleIOGenericIO`; `mms.floating_point` =
     `08:3d:2a:51:55`, exactly the octets this module's `Float.parse` consumes;
     `mms.unconfirmedService` = 0 on all seven reports; `mms.moreFollows` = False.
   - *our own MMS*: the client's CR, the 187-octet CONNECT (`mms.proposedMaxServOutstandingCalling`
     = 5, contexts 1/3/1), **our server's ACCEPT with `acse.result` = 0**, our read request
     (`mms.confirmedServiceRequest` = 4, invokeID 1, domainId `simpleIOGenericIO`) and our read
     response (`mms.floating_point` = `08:42:2a:00:00`, i.e. 42.5).
   - *captured GOOSE*: `gocbRef`, `datSet`, `timeAllowedtoLive` = 500, `confRev` = 1, `stNum` = 1,
     `sqNum` = 0/1/2/3, `numDatSetEntries` = 3/3/3/4, `appid` = 0x03e8 — all agreeing with this
     module's decode.
   - *our own GOOSE*: five frames from the `Publisher`. Wireshark reads `stNum` 1,1,1,1,**2** and
     `sqNum` 0,1,2,3,**0** across the state change; `timeAllowedtoLive` 10, 16, 32, 64 and back to
     10, i.e. the backoff ladder and its derived TAL; `vlan.id` = 100; `goose.t` decoded as
     `Nov 14, 2023 22:13:20.000000000 UTC` from `UtcTime.fromMillis(1_700_000_000_000)`, and
     `22:13:20.059999942` on the state-change frame — an independent confirmation of the `UtcTime`
     binary-fraction encoding.
   - *SV, both*: our frame (`svID` `ZIGMU01`, `smpCnt` 1234, `confRev` 2, `smpSynch` 2) and the
     captured one (two ASDUs `svpub1`/`svpub2`, `smpCnt` 1/2/3).

4. **15 byte-exact captured control-model goldens** (`controlgoldens.zig`). Two captures through the
   same recording proxy: a third-party control **client** driving a third-party control **server**
   (`.third_party` — nothing in this repo touched those octets), and **this module's client driving
   that same third-party server** (`.ours`), which is the only way the failure path was obtained —
   the oracle's own client only ever takes the happy path. Pinned: a `ctlModel` read and its answer;
   the `GetVariableAccessAttributes` type description of a select-before-operate object; an `Oper`
   write under `direct-with-normal-security` and its positive answer; the `SBO` **read** that is a
   normal-security select and the object reference it answers with; the `SBOw` **write** that is an
   enhanced-security select; `Oper` writes under `sbo-with-normal-security` and
   `sbo-with-enhanced-security`; three `CommandTermination+` indications; and — from the run against
   us — an `Oper` written **without a select**, the `LastApplError` the IED pushed
   (`AddCause = Object-not-selected`, `ctlNum` 200, our own `origin` echoed back) and the negative
   write response that followed it. Assertions over the whole table:
   - every frame decodes through all five layers;
   - every control structure **re-encodes to the identical octets from its decoded fields**, and
     every whole `Oper`/`SBOw` write request is rebuilt from its decoded object name and decoded
     command and compared against the captured PDU — i.e. this module could have sent the frame the
     third-party client sent;
   - every unsolicited frame classifies correctly, positive termination versus `LastApplError`;
   - **this module's own `TypeSpecification` for a `sbo-with-normal-security` control object is
     byte-identical to the one the real IED sent** — every member, name, order and width;
   - a coverage assertion fails if the table stops containing all four control models, both select
     shapes, the terminations and a `LastApplError`.

5. **Live round trip, our client → a real IEC 61850 server** (`root.zig`, gated on
   `IEC61850_TEST_SERVER`). Against a live `libiec61850` `server_example_basic_io` on `127.0.0.1:102`
   inside a netns, the run completed the whole five-layer association and then: browsed **1 logical
   device**; browsed **304 named variables** of it (the 6675-octet reply, live); browsed **3 data
   sets**; read a floating-point measurement; wrote a `VisibleString` description **and read it
   back**; got a per-object `object-non-existent` for a variable that does not exist (rather than a
   fatal error); read a whole data set (**4 values**); read the unbuffered RCB, enabled reporting,
   triggered a general interrogation and **received a real `InformationReport` with 4 entries**
   through the report handler; and disabled reporting again. Printed output:
   `live IEC 61850 client: lds=1 vars=304 datasets=3 mag=0.6755 write=true readback=true
   dataset_values=4 rcb=true reports=1 report_entries=4 vendor=(unsupported)`

6. **Live control, our client operating a real IED** (`root.zig`, gated on `IEC61850_TEST_CONTROL`).
   Against a live third-party control server inside a netns, this module's client read each object's
   `ctlModel`, ran the whole state machine for it, and then **read `stVal` back over MMS** to prove
   the IED moved rather than that our write returned. Printed output:
   `live IEC 61850 control: models=direct_with_normal_security/sbo_with_normal_security/
   direct_with_enhanced_security/sbo_with_enhanced_security operated=4 terminations=2
   notifications=3 unselected_operate_add_cause=object_not_selected` — all four models operated, both
   enhanced ones waited for and received a real `CommandTermination`, and an `Oper` written to a
   select-before-operate object without selecting it came back with a real `LastApplError` naming
   `Object-not-selected`.

7. **Live control, a real IEC 61850 control client operating *our* objects** (`root.zig`, gated on
   `IEC61850_TEST_LISTEN_CONTROL`). A third-party control client was pointed at this module's
   `Server` standing up four control objects, one per `ctlModel`. It printed
   `SPCSO1..SPCSO4 operated successfully` and **`Received CommandTermination+.`** on both enhanced
   objects, and correctly reported the one object we do not model as not found. Our side printed
   `live control server: peers=1 reads=8 writes=5 selects=2 operates=4 rejections=0 stVal_now=4/4`.
   That an independent stack completed select-before-operate against us, accepted our
   `GetVariableAccessAttributes` type description, and consumed our unsolicited `CommandTermination`
   is the strongest evidence for the server-side control encoders.

8. **Live SCL round trip: the resolver against the IED the file configures** (`root.zig`, gated on
   `IEC61850_TEST_SCL_FILE` + `IEC61850_TEST_SCL_SERVER`). For each configuration file, the IED it
   configures was started, this module parsed the **same file**, resolved its type graph, and
   compared the resulting MMS names against that IED's own `GetNameList` **in both directions**.
   Twelve files, **3,273 names, every one matched, none missing and none invented**:

   | file | names | file | names |
   |---|---|---|---|
   | `simpleIO_ltrk_tests.icd` | 602 | `simpleIO_direct_control.cid` | 304 |
   | `wtur.cid` | 379 | `server_example_files` variant | 278 |
   | `simpleIO_control_tests.cid` | 370 | `simpleIO_direct_control_goose.cid` | 215 |
   | `complexModel.cid` | 350 | `mhai_array.cid` | 191 |
   | `sampleModel_with_dataset.cid` | 170 | `substitution_example.cid` | 134 |
   | `cid_example_deadband.cid` | 163 | `sg_demo.cid` | 117 |

   Between them these cover: all four control models; report control blocks buffered and unbuffered,
   indexed and not; GOOSE control blocks with their `DstAddress`; log control blocks; a setting-group
   control block with `SE`→`SG` mirroring; arrays of sub-data-objects; `PhyComAddr`; the edition-2
   `OR`/`BL` and edition-2.1 `SR` functional constraints; and a wind-turbine model (IEC 61400-25)
   that shares nothing with the others. Two knobs were needed and are `Options` fields rather than
   guesses: the buffered-RCB timestamp spelling (`TimeofEntry` on this oracle, `TimeOfEntry` in
   IEC 61850-8-1) and whether the SGCB exposes `ResvTms`.

9. **Live round trip, real IEC 61850 clients → our server** (`root.zig`, gated on
   `IEC61850_TEST_LISTEN`). Three third-party clients were pointed at our `Server` in sequence:
   `mms_utility -d` associated and **printed our domain**; `iec61850_client_example1` associated,
   **read our floating-point value back as `42.500000`** and wrote a `VisibleString` into our
   writable variable; `iec61850_client_example2` associated and listed the logical device. Our side
   printed `live IEC 61850 server: peers=3 associated=true reads=3 writes=1 name_lists=3`. That an
   independent stack accepted our COTP CC, session ACCEPT, presentation CPA (with its positional
   result list), ACSE AARE and MMS `Initiate` response is the strongest evidence for the
   server-side encoders.

10. **Live GOOSE replay** (`root.zig`, gated on `IEC61850_TEST_GOOSE_HEX`). The four frames captured
   from the third-party publisher on the veth pair were fed through the `Subscriber`: all four
   decoded, three were in-sequence refreshes, no gaps, and the subscriber reported the data usable.

All live tests passed in Debug **and** in `--release=fast`, and all six print `SKIPPED: …` and pass
when no peer is present.

**Wireshark cross-check of the control model.** `rawshark` was pointed at both control captures with
the same `-d proto:tpkt` dissection chain:
- *their client → their server*: `mms.confirmedServiceRequest` = 4/6/5 in the read-ctlModel →
  getVariableAccessAttributes → write-Oper order this module now reproduces, and
  `mms.unconfirmedService` = 0 on each `CommandTermination`.
- *our client's own `Oper`*: `mms.utc_time` = `Nov 14, 2023 22:13:20.000000000 UTC` (from
  `UtcTime.fromMillis(1_700_000_000_000, 10)`), `mms.boolean` True (`ctlVal`) and False (`Test`),
  `mms.unsigned` = 200 (`ctlNum`), `mms.integer` = 2 (`orCat` = station-control).
- *the IED's `LastApplError` to us*: `mms.vmd_specific` = `LastApplError` — independent confirmation
  that the name is VMD-scoped, not domain-scoped — with `mms.integer` = 0 (`Error`), 2 (`orCat`) and
  **18** (`AddCause` = Object-not-selected) and `mms.unsigned` = 200.
- *our server's own `CommandTermination+`*: `mms.unconfirmedService` = 0 with `mms.boolean`
  True/False and `mms.unsigned` = 1, on the two frames a third-party client reported as
  `Received CommandTermination+.`

### What is self-derived

- **Everything the oracle's example model does not contain.** The captured IED is
  `libiec61850`'s shipped example (`simpleIOGenericIO`, `testComplexArray`), so: buffered report
  control blocks (`BR`) were read as *names* but never enabled or driven, `EntryID`/`TimeOfEntry`
  are decoded from the documented layout and unit-tested rather than captured; the segmented-report
  path (`OptFlds.segmentation`, `SubSeqNum`, `MoreSegmentsFollow`) is unit-tested only; the
  `data_reference` option in `OptFlds` is unit-tested only, because the captured IED never set it.
- **`Data` alternatives the capture never carried**: `array`, `bcd`, `booleanArray`, `objId`,
  `mMSString`, `generalized-time`, and `real` (`[8]`, withdrawn). These are encode/decode round-trip
  tested against their documented tags and widths, not against third-party octets.
- **File services beyond what was captured.** `FileOpen` and `FileDirectory` requests are byte-exact
  against the capture, and the `confirmed-ErrorPDU` the server answered `FileDirectory` with is
  pinned; but no successful `FileOpen`/`FileRead`/`FileClose` sequence was obtained (the example
  server had no file store), so `FileOpen-Response`, `FileRead-Response` and
  `FileDirectory-Response` are decoded from the documented layouts and unit-tested only.
- **`Identify`.** The captured server does not implement it (the live run printed
  `vendor=(unsupported)`), so the request/response pair is round-trip tested against this module's
  own encoder, not against a third party.
- **`DefineNamedVariableList` / `DeleteNamedVariableList`.** Encoders and the response decoders are
  unit-tested; no oracle exchange was captured.
- **The GOOSE retransmission timing itself.** The captured publisher was observed at its heartbeat
  only; the ladder, the derived TAL, the state-change reset and the TAL-expiry detection are
  validated against the standard's description **with an injected clock**, and cross-checked by
  Wireshark reading the TAL values our publisher emits — but no third-party *subscriber* was driven
  through a real outage.
- **SV publisher/subscriber timing** is not implemented at all (see Deferred); only the codec is,
  and it is validated in both directions against Wireshark and a captured frame.
- **The 802.1Q path.** The captured publisher emitted untagged frames; the tagged path is
  round-trip tested here and confirmed by Wireshark reading `vlan.id` off **our** frames, but no
  third-party tagged publisher was available.
- **Indefinite-length BER.** No captured frame used it; the decode path is unit-tested (including
  nesting and a missing terminator) against X.690's documented rules. This module never *emits* it.
- **The oracle is an example server, not a real IED.** No vendor relay, merging unit or RTU was
  available. Firmware-specific quirks (access levels, vendor extensions, real substation SCL) are by
  definition not covered — though the control model and SCL are now driven end to end against a
  third-party stack in both directions, which was not true before.
- **Control paths the oracle's model does not contain.** `operTm` (a timed operate) is encoded and
  decoded and shape-tested, but no captured object had it. `Cancel` is driven against **our own**
  server, not against the third party's — the oracle's example client never cancels. The
  `AddCause`es other than `Object-not-selected` are produced by this module's own `Point` and
  round-tripped, not observed from a third-party IED: no oracle model exposes an interlock, a
  synchrocheck or a health block. A `ctlVal` other than `BOOLEAN` (a DPC's `Dbpos`, an INC's
  integer, an APC's float) is encoded generically and unit-tested, never captured.
- **The buffered report control block's attribute list, and the SGCB's `ResvTms`,** are self-derived
  from IEC 61850-7-2 and then reconciled against what the oracle serves; the two spellings and the
  optional attribute are `Options` fields precisely because there is no single right answer.
- **SCL emission is not implemented at all** — this is a parser and a resolver, not a writer. See
  Deferred.
- **The SCL `Substation` section is skipped**, not parsed: `Scl.has_substation` records that it was
  there (which is what `kind()` uses) and nothing more. Single-line diagrams are a configuration-tool
  concern, not a client's.

### Fuzz + hostile input

20 `std.testing.fuzz` sweeps, all asserting "typed error or valid result, never a panic and never a
hang":

- `ber.decode` over arbitrary bytes — anything that decodes with a definite length must **re-encode
  to the identical octets**; plus an iterator sweep with a guard counter, and a tag/length
  round-trip sweep over arbitrary tag numbers and lengths.
- `tpkt.decode` and `tpkt.Framer` fed arbitrary stream bytes in chunks, with a guard that fails if
  `next` ever yields without consuming input.
- `cotp.decode` — a CR/CC must re-encode verbatim, a DT exactly.
- `session.decodeConnect`/`decodeHeader`/`decodeDataTransfer` plus full parameter iteration.
- `presentation.decodeCp`, `decodeUserData` against a real context table, and `PdvIterator`.
- `acse.decodeAarq`/`decodeAare`/`classify`.
- `mmsdata.Data.decode` + `validate` + full member walk.
- `mms.decode` plus every service body decoder, with guarded iteration over access results,
  identifiers and report entries.
- `acsi.parseAcsi`/`parseMms` — anything that parses must re-serialise and re-parse to an equal
  reference.
- `report.decodeInformationReport` and `Rcb.decode` in both flavours.
- `goose.Frame.decode` + `Pdu.decode` — anything that decodes must re-encode to the identical PDU.
- `sv.Asdu.decode`/`SavPdu.decode` with the same re-encode assertion.
- `server.handle` over arbitrary packets, both before and after association.
- `control.Command.decode` and `control.LastApplError.decode` over arbitrary `Data` — anything that
  decodes must re-encode and re-decode to the same fields, including which optionals were present.
- `control.classify` over arbitrary `InformationReport` bodies.
- `control.Point` driven through 32 random select/operate/cancel/tick steps with random owners,
  `ctlNum`s and clock jumps, asserting the invariant that an **unselected point never holds an owner
  or a deadline** — which is what makes a leaked select impossible.
- `scl.parse` + `scl.resolve` over arbitrary bytes, and over a hostile identifier glued into a valid
  SCL skeleton so the *resolver* rather than the lexer is what gets exercised; every name it
  produces must be a legal MMS item id within `acsi.max_reference_len`.

Explicit hostile-input tests (not fuzz) cover every case named in the task and more: a TPKT shorter
than its header, a bad version, a non-zero reserved octet, a length below the header, a length that
disagrees with the payload in both directions, a packet larger than the framer's storage; a COTP
`LI` of zero and one pointing past the buffer, an unknown TPDU code, transport class 4, a `DT` with
`LI != 2`, a variable-part parameter running off the end, a dangling parameter code; a session
header shorter than its length, a parameter running past its group, a CONNECT with no user data, a
dangling PI; a presentation mode-selector that is not normal mode, a context-list entry that is not
a SEQUENCE, a **result list of the wrong length**, a PDV on an **undefined** context and one on a
**rejected** context, and a context table pushed past its ceiling; an ACSE user-information whose
EXTERNAL has no payload and one whose length overruns; a BER length that overruns, a reserved `0xFF`
length octet, more length octets than a `usize`, a non-minimal long-form tag, a long-form tag
encoding a short-form number, six continuation octets, an **indefinite length with no terminator**,
an indefinite length on a primitive element, and a **512-deep indefinite nest**; a `Data` tag that is
not an alternative, a primitive `structure`, a constructed `integer`, a **64-deep `Data` nest** (both
standalone and buried in a GOOSE frame), a `UtcTime` with a reserved `TimeAccuracy` (25 and 30) and
with the wrong width, a `TimeOfDay` past midnight and of the wrong width, an MMS float whose
exponent width disagrees with its payload, a bit string with an unused count above 7; an MMS
confirmed request with no service and one whose invoke id is not an INTEGER, an access-result list
whose member is not a `Data` alternative, a `rejectPDU`; a report that ends before `OptFlds`
promised, a report field of the wrong `Data` alternative, an access-result failure inside a report,
an RCB structure that stops early; a GOOSE `Length` that overruns, one below the eight-octet base,
one that truncates the PDU, an `allData` count contradicting the entries in **both** directions, a
non-GOOSE EtherType, a dangling VLAN tag, a PDU missing a mandatory field; SV fixed-width fields of
the wrong width and a `noASDU` disagreeing with `seqASDU`; and roughly forty malformed object
references in both syntaxes.

For the control model and SCL specifically, every case is covered by an explicit test: an SCL type
reference that does not resolve (at all three levels — `lnType`, `DO type`, `DA type`), a **direct**
cyclic `DAType`, a **two-step** cyclic `DAType` that a naive "same as my parent" check misses, a
cyclic `SDO` caught by the depth budget instead, a `DAI` whose value contradicts its `bType`
(`BOOLEAN` = `"maybe"`, `INT8U` = `"400"`, an `Enum` value not in its `EnumType`, a `VisString32` of
forty characters), an `FCDA` pointing at a data object that is not in the `LNodeType`, an unknown
`bType` (refused unless the caller opts in), a document that is not SCL, a DOCTYPE-bearing document,
an IED name the file does not contain; a control response whose `ctlNum` does not match (refused, and
the machine stays waiting rather than wrongly finishing), a `LastApplError` with an out-of-range
`AddCause`, a `CommandTermination` for a control object under the wrong functional constraint (not
classified as a control notification at all), an ordinary `RPT` report that must **not** be swallowed
by control classification, a select that expires mid-operate on the client side and one that expires
at the server, an operate on an object another client holds, an `Oper` whose `ctlNum` does not repeat
the `SBOw`'s, a second operate while one is executing, a `Cancel` with nothing to cancel, an
execution that never completes, and a state machine driven out of order.

## Threat model

IEC 61850 is **unauthenticated and unencrypted** by design, and its two halves fail differently:

- **MMS on TCP 102.** Anyone with a path to the port can read any data attribute and write any
  setpoint. There is no authentication step in the protocol — the AP/AE titles in the AARQ are
  identifiers, not credentials. This module's job is therefore robustness and containment: hostile
  or corrupt bytes from a misbehaving IED, a hostile client or a MITM resolve to typed errors at
  every decode entry point; nothing allocates and every buffer is caller-supplied and bounded, so a
  hostile peer cannot drive memory growth; the context table, the `Data` depth, the report entry
  count and the COTP reassembly buffer are all hard ceilings.
- **GOOSE on the station bus.** There is **no integrity protection at all**. Anyone who can put a
  frame on the LAN can forge one with a higher `stNum` and a plausible `gocbRef`, and a subscriber
  has no way to tell. The `confRev` check, the `numDatSetEntries` cross-check and the TAL liveness
  window are **consistency** mechanisms, not security ones: they catch misconfiguration and loss,
  not an attacker. IEC 61850-90-5 / IEC 62351-6 signing is **not implemented** — the `security [12]`
  field is skipped on decode and never emitted. Physical and VLAN segregation of the station bus is
  the actual control.
- **Writing is dangerous and is spelled out.** `FunctionalConstraint.isOperational` names the five
  constraints (`CO`, `SP`, `SV`, `SG`, `SE`) under which a write changes what the plant does rather
  than what a description says. Nothing in this module writes implicitly, but nothing stops a caller
  either. The **control model is now implemented** — select-before-operate, `ctlNum`, the originator,
  the `Check` overrides, `AddCause`, `CommandTermination` — so a client has the interlocks a real one
  applies; a caller writing `CO` attributes by hand is still bypassing them, and
  `control.controlAttribute` exists partly so a caller can *detect* that it is about to.
- **The `Check` bits are a request to skip a safety interlock.** Setting `synchrocheck` or
  `interlock-check` is an override, and `Point.allow_check_override` is false by default: whether an
  override is permitted is the IED's decision. `origin`/`orIdent` is an **audit field, not a
  credential** — IEC 61850 has no authentication, so an attacker can claim any originator, and a
  `LastApplError` echoing "station-control" proves nothing about who sent the command.
- **SCL is untrusted input.** A `.scd` arrives from an engineering tool and describes what a client
  will then go and operate. It is parsed with the hardened `xml` sibling (DOCTYPE rejected, no
  external entities, bounded depth), every type reference is resolved with a cycle check and a depth
  bound, and every configured value is checked against its declared type — but a *semantically*
  hostile SCL that points a client at the wrong breaker is not something any parser can catch.
- **`ndsCom` and `test` are honoured, not ignored.** A publisher's `test` flag and its "needs
  commissioning" flag are surfaced as distinct subscriber events precisely because acting on a test
  frame is a real incident class.
- **Deployments must put transport security under MMS** — IEC 62351-4 (TLS on 102) or a VPN. This
  module implements none and callers should hand the `Transport` seam an already-terminated stream,
  exactly as the repo's BYO-TLS rule (CONVENTIONS §2) prescribes.
- **The `Server` is a simulator, not an IED.** No SCL model, no control model, no access control, no
  reporting engine. Do not put it on a network where something might mistake it for real equipment.

## Deferred

Honest list of what a full IEC 61850 implementation has and this one does not. IEC 61850 is
enormous; this module ships MMS read/write/browse, the control model, SCL parsing and resolution,
and GOOSE publish/subscribe, each done properly.

**Driven end to end (client and server, live against a third party):** association, `GetNameList`
at all three scopes, `Read` and `Write` over named variables and named variable lists, RCB read /
enable / general interrogation / disable, `InformationReport` reception, and — new — **the whole
control model**: `ctlModel`/`sboTimeout` reads, the `SBO` read and the `SBOw` write, `Oper` under all
four models, `CommandTermination` in both directions, `LastApplError` received from a real IED, and
`GetVariableAccessAttributes` on a control object answered by this server to a real client's
satisfaction.

**Driven against a real IED's own name space (not against a peer, but against ground truth):** the
whole SCL parse and type resolution — twelve configuration files, 3,273 names, exact in both
directions against the `GetNameList` of the IED each file configures.

**Codec-only (encoded and decoded, unit-tested, never driven against a peer):** `Identify`,
`GetVariableAccessAttributes` for anything that is **not** a control object (the general type tree is
decoded but this server only describes control objects),
`GetNamedVariableListAttributes`, `DefineNamedVariableList`, `DeleteNamedVariableList`, all four file
services' *responses*, buffered report control blocks, segmented reports, `data_reference` reports,
SV in both directions, the alternate-access sub-specification (preserved verbatim, not interpreted),
`operTm` on a control command, a `ctlVal` that is not a `BOOLEAN`, and every `AddCause` other than
`Object-not-selected` (produced and consumed by this module's own two halves, never observed from a
third party — no oracle model exposes an interlock or a synchrocheck).

Not implemented at all:

- **Emitting SCL.** This is a parser and a resolver; there is no writer. A round trip
  (parse → modify → serialise) would need the whole IEC 61850-6 schema including the sections this
  module deliberately skips, and a canonicalisation story for a format whose tools all differ. **We
  do not emit SCL.**
- **The SCL `Substation` section** (single-line diagram, voltage levels, bays, conducting equipment,
  `LNode` bindings) and `Private`/`Text` elements. `Scl.has_substation` records that it was present
  and nothing else. Also unparsed: `Services` capabilities, `SampledValueControl`, `Inputs`/`ExtRef`
  (the subscription bindings edition 2 uses), and `<Log>` bodies.
- **The server-side reporting engine.** The `Server` answers reads and writes and now enforces the
  control model, but it does not evaluate `TrgOps`, buffer entries, assign `EntryID`s or emit
  report `InformationReport`s. Report *decoding* and RCB *manipulation* are complete on the client
  side; the only unsolicited PDUs this server emits are control notifications.
- **Logging** (`LG`, `ReadJournal`, `GetJournalStatus`) — SCL's `LogControl` resolves into the right
  MMS names, but the log itself, the journal services and the entry store are not here.
- **Setting-group *services*** (`SelectActiveSG`, `SelectEditSG`, `ConfirmEditSGValues`). SCL's
  `SettingControl` resolves into `LLN0$SP$SGCB` and its attributes, and the `SE`→`SG` mirroring is
  done, but nothing switches a group.
- **Control extras:** `Time-activated operate` beyond carrying `operTm` on the wire (nothing
  schedules it), `sboClass` (`operate-once` vs `operate-many` — a select is always released by the
  operate here), `opRcvd`/`opOk`/`tOpOk` under the `OR` constraint (resolved as names, not driven),
  and multi-client `1-of-n` control across several objects.
- **GOOSE re-transmission on the *subscriber* side for redundancy** (PRP/HSR duplicate discard), and
  **GSSE** (the pre-2003 `0x88B9` framing) entirely.
- **SV publisher/subscriber timing.** SV runs at 4000 or 4800 frames a second against a hard jitter
  budget; that belongs with a real-time scheduler, not a codec. Only the frame codec is here.
- **IEC 62351 security**: no TLS on 102, no GOOSE/SV signing (`security [12]` is skipped), no
  certificate handling, no RBAC.
- **IEC 61850-90-5** routable GOOSE/SV over UDP.
- **MMS services outside the IEC 61850 profile**: domain download/upload, program invocations,
  semaphores, event conditions/actions/enrollments, scattered access, named types, `Status`,
  `Cancel`. Their tags are named in `mms.Service` and nothing more.
- **Multiple concurrent outstanding requests.** `Initiate` negotiates `maxServOutstanding` in both
  directions and this client always uses 1, which is what most IEC 61850 clients do in practice; the
  invoke id is nevertheless matched on every response, so an out-of-order reply is handled.
- **Reconnection, retry and keepalive.** The client performs one exchange per call and surfaces a
  transport failure; a production deployment wires reconnection into its own supervisor. There is no
  timer anywhere in this module — the control model's `sboTimeout` and termination deadlines expire
  because the caller calls `tick`, not because anything here owns a clock.
- **`tshark`** is not installed and cannot be without root; the cross-check was done with
  **`rawshark`**, the same Wireshark 4.6.4 dissection engine, and is reported above.

## Status

`gap · any (pure codecs + state machines; only the optional TcpTransport touches std.Io.net) ·
both (client + server, publisher + subscriber) · single_owner` + deps: `xml` (SCL only; every other
file is std-only and allocation-free) — canonical source is `pub const meta` in src/root.zig.

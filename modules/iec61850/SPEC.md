# iec61850 — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## Design & invariants

Two stacks sharing one BER codec. Every wire struct uses explicit shifts in its encode/decode
rather than a `packed struct`, so the octet layout never depends on Zig's bitfield-packing rules,
and nothing anywhere allocates except `scl` and `sclwrite`, which handle a document of unbounded
shape and say so.

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

### Reporting, logging and setting groups

- **`BufTm` coalesces, it does not delay.** A trigger opens an entry with a deadline `BufTm`
  milliseconds out; every further trigger on the same data set inside that window merges into the
  *same* entry, OR-ing the inclusion bit and the reason. One report leaves, not five. Getting this
  wrong is the difference between a report and a storm, and `BufTm = 0` is the "every change is its
  own report" case, not a special one.
- **The B in BRCB is the retention, and retention needs a bound.** Events that happen while
  `RptEna` is false — or while no client is associated at all — are kept, and a client that
  re-enables with the `EntryID` it last saw resumes from there. The buffer is a ring of caller-owned
  entries over a caller-owned arena split into equal slots: when it wraps over an entry the reader
  has not seen, `BufOvfl` is raised on the next report and cleared once reported. A resume point
  that has fallen out is `error.EntryIdNotFound`, not a silent restart. A URCB's buffer is purged on
  disable, which is the whole of the other definition.
- **`OptFlds` decides the report's shape, so the encoder and the decoder must agree bit for bit.**
  Every one of the 512 combinations of the nine defined bits is encoded here and decoded by
  `report.zig` — the same decoder that was validated against captured third-party reports — and
  checked field by field. A positional format with nine optional prefixes has no room for "probably
  right".
- **There is no clock.** `BufTm` and `IntgPd` are deadlines the caller advances with `tick`, exactly
  like the control model's `sboTimeout`. A report is *encoded* lazily, when the caller drains
  `pendingNotification`, straight out of the buffer entry — so a report nobody collects costs
  nothing beyond the entry it already occupies.
- **A log is a report nobody was listening to**, and it reuses the same `TrgOps`, the same data set
  and the same `Source` seam. What differs is the store: a bounded circular log whose oldest entry
  falls out visibly, through `OldEntr`/`OldEntrTm` moving forward, rather than silently. A query
  that spans the purge returns what survived.
- **The log's `ReasonCode` is seven bits wide, a report's is six.** IEC 61850-7-2 adds
  `application-trigger` for a log entry. A client that assumes six reads the wrong bit; the captured
  third-party entries use the seven-bit form and so does this encoder.
- **An uncommitted setting-group edit must be invisible.** Writing `LN$SE$…` changes the edit
  buffer; reading `LN$SG$…` still returns the *active* group's value, even when the group being
  edited **is** the active one. Only `CnfEdit = true` copies the buffer into the selected group, a
  confirm with no preceding edit is refused rather than committing whatever was in the buffer, and
  `SelectEditSG` pre-loads the group so that editing one attribute and confirming does not blank the
  rest. A real IED refuses an `SE` read with no edit group selected; so does this one.
- **`report.Report` is decoded into caller-owned storage, not returned by value** (audit F4).
  `Report.decode(out: *Report, results: *mms.AccessResultIterator) Error!void` and
  `decodeInformationReport(out: *Report, body: []const u8) Error!void` write into `out` instead of
  returning a `Report` — the struct is 9,344 bytes (dominated by the fixed
  `entries: [max_entries]Entry` array), and returning it by value cost a full struct copy on the
  client's report-receive hot path (measured: 3,514 ns/call before, 514 ns/call after, one 106-octet
  captured report per call, `ReleaseFast`, `IEC61850_BENCH=1 scripts/capped zig build
  test-iec61850 -Doptimize=ReleaseFast`). `ReportHandler.on_report` follows the same contract one
  hop downstream: it takes `r: *const report.Report`, a borrow into the client's own decode-scratch
  storage, valid only for the duration of the call. **Partial-failure contract**: on an error, some
  scalar fields of `out` may already be overwritten while others still hold whatever `out` held
  before the call (decode is not transactional across the whole struct — see `Report.decode`'s doc
  comment) — but `out.entries`/`out.entry_count` specifically are never left showing a mix of the
  old and new report, because every fallible read completes before the one loop that writes
  `entries` runs, and `entry_count` is reset to `0` as soon as `rpt_id`/`opt_flds` succeed, before
  any of the fields that can still fail. A caller reusing one `Report` across calls therefore never
  observes `included()` returning entries misattributed to a report that failed to decode.

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
- **Writing SCL is a different problem from reading it**, and the trap is defaults. SCL is full of
  optional attributes whose value a reader supplies when they are absent, so a writer that makes
  every one of them explicit hands the next tool a document that means something slightly different
  — one flag at a time. `sclwrite` therefore emits an attribute **only when it differs from the
  schema default**, and keeps the *source document's namespace*, because that URI is how a reader
  chooses which edition's defaults to apply. Both rules were forced by a third-party model generator
  disagreeing with an earlier, more explicit emission; the same exercise found that
  `OptFields/@bufOvfl` defaults to **true**, which this module's parser had been getting wrong.
- **The round trip is checked through the resolver, not through the text.** Attribute order,
  whitespace and the position of `LN0` are the writer's business; what must be preserved is the flat
  list of MMS names, and that is what 44 real configuration files are compared on.
- **`scl` and `sclwrite` are the only files here that allocate**, and they say so: an SCL document
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

### Reporting, logging, setting groups and SCL emission — what actually ran

All of this was driven against the same third-party stack, built with `cmake` and run as a black
box. Its **shipped `.icd`/`.cid` files were treated as configuration data**, its console output and
build log were read, and **no source file of it was opened**; every layout below was derived from
the published IEC/ISO specifications first and then confirmed against octets on the wire.

**A third-party client subscribing to reports from our server** (env-gated test
`IEC61850_TEST_LISTEN_REPORT`, model deliberately named the way the reference clients are
hard-wired). Two different reference clients were pointed at it, through a TPKT-aware recording
proxy:

- Its *reporting* example: read the URCB, wrote `Resv`/`DatSet`/`TrgOps`/`RptEna`/`GI` in one
  five-variable `Write` (all five answered `success`), then printed **46 reports** it had decoded —
  8 member-inclusions with reason `general-interrogation` and 44 with reason `data-change`, each
  labelled with the member's own reference (`simpleIOGenericIO/GGIO1.Ind2.stVal[ST]`), its value and
  the `TimeOfEntry` our injected clock produced (`Mon Nov 13 23:13:20 2023`).
- Its *first* example, which unlike the reporting one leaves `IntgPd` on: **integrity** reports
  (its reason code 8) as well as general-interrogation ones, arriving on the server's own schedule
  with no request in flight.
- Its *log* example, hard-wired to `TestIEDGenericIO/LLN0$EventLog`: wrote `LogEna`, read our LCB
  and printed all nine members in order, then issued a `ReadJournal` and printed **15 journal
  entries** — `EntryID`, occurrence time, the member's reference, its value and the `ReasonCode`
  pseudo-variable — out of our bounded store.
- Its generic MMS browser read, and decoded correctly, our `LLN0$SP$SGCB`
  (`{3,1,0,false,…}`), an `SG` setting value, and the **fourteen-member BRCB**
  (`{Events2,false,…/LLN0$Events,1,0111101010,50,0,011011,1000,false,false,00000000000001fd,…,0}`).
  The same browser **segfaults** on our 15-entry `ReadJournal` response; the same vendor's *library*
  client parses that identical response without complaint and so does Wireshark, so the crash is in
  that tool, not in our octets. Reported here because it happened, not because it means anything
  about the encoding.

**Byte-exact goldens, captured from that stack and re-encoded by us:**

- The **BRCB structure** a real IED returns, member by member — which is how the member *order* in
  `report.Rcb.decode` was corrected: a BRCB has **no `Resv`** and appends `PurgeBuf`, `EntryID`,
  `TimeOfEntry` and `ResvTms` after `GI`. The previous layout read `PurgeBuf` out of `DatSet`.
- The **LCB structure** (`LogEna`, `LogRef`, `DatSet`, `OldEntrTm`, `NewEntrTm`, `OldEntr`,
  `NewEntr`, `TrgOps`, `IntgPd`).
- The **SGCB structure**, which our emitter now reproduces **octet for octet**.
- A **`ReadJournal` request** and its **response** — both rebuilt octet for octet by this module's
  encoders from their decoded parts. That capture is also where `entryToStartAfter`'s context tag
  (`[5]`) and the log `ReasonCode`'s **seven**-bit width came from; a six-bit reader gets the wrong
  bit.
- The **GI report** a real IED emits: our encoder reproduces those 100 octets exactly from a
  `sweep(.general_interrogation)`.

**Wireshark cross-check (`rawshark`, `-d proto:tpkt`, Wireshark 4.6.4), on our own output:**

- our reports: `mms.vmd_specific` = `RPT` and `mms.unconfirmedService` = 0 on each, with
  `mms.boolean` reading `False,False,False,False` on the GI report and `True,True,False,False` on a
  later one — the same values the third-party client printed;
- our RCB read response: `mms.unsigned` = 1, 50, 0, 1000 (`ConfRev`, `BufTm`, `SqNum`, `IntgPd`);
- our `ReadJournal` **request and response**: `mms.journalName`, `mms.rangeStartSpecification`, and
  on the response 15 × `mms.entryIdentifier`, `mms.entryForm` = 2 (data), `mms.occurenceTime`
  decoded as `Nov 13, 2023 22:14:33.560000000 UTC`, and `mms.variableTag` alternating the member
  reference with `ReasonCode`. An independent ASN.1 decoder agreeing field by field is what makes
  the journal layout more than a reading of the standard.

**Report segmentation, driven and dissected.** A model whose `LLN0$Events` data set carries twelve
660-octet members was served to the reference stack's own reporting client, with
`OptFlds.segmentation` and `OptFlds.data_reference` set. The negotiated ceilings were
`localDetailCalling` = 65000 clamped to this server's 8192-octet send buffer and a COTP TPDU size of
**8192**, giving a segment budget of **8128**; `data_reference` is what makes the report larger than
a plain read of the same data set (the read carries only the values), which is the gap segmentation
has to live in, because a class-0 TPDU can never exceed 8192 and this module does not split one PDU
across several TPDUs.

- The reference client's report handler was called **twice** for the one report and printed all
  twelve members, in order, with the right references and reason codes: eleven from the first
  segment and the twelfth from the second. It does **not** itself reassemble — it delivers each
  segment to the handler separately — and the fact that it nevertheless named every member correctly
  is the strongest evidence available for the choice made here: **each segment carries its own
  full-width inclusion bit string**. Had the whole report's bit string been repeated in every
  segment, a client that does not track a running index would have mis-assigned every value in the
  second segment.
- `report.Reassembler` is the client half that *does* put them back together, and it is driven
  against our own server over an in-memory wire as well.
- The exchange was captured and dissected with **rawshark 4.6.4** (`-d proto:tpkt`, TCP streams
  reassembled into TPKT frames first). The two segments came out as 7894 and 823 octets, and
  Wireshark's own MMS dissector read them as: `mms.iec61850.rptid` = `Events1` on both,
  `mms.iec61850.datset` = `simpleIOGenericIO/LLN0$Events` on both, `mms.iec61850.timeofentry` =
  `Nov 13, 2023 22:13:20.060000000 UTC` on both, `mms.iec61850.confrev` = 1 on both,
  `mms.listOfAccessResult` = **42** then **12** (nine header fields plus three per member: eleven
  members, then one), and — for the two fields the dissector has no IEC 61850 name for and therefore
  renders generically — `mms.unsigned` = **0 → 1** (`SubSeqNum`) and `mms.boolean` = **True → False**
  (`MoreSegmentsFollow`). No frame in the capture raised `_ws.malformed`.
- Hand-decoding the same frames confirms the rest: the inclusion bit string is `84 03 04 FF E0`
  (twelve bits, members 0–10) on the first segment and `84 03 04 00 10` (member 11) on the second,
  and `SqNum` is `86 01 00` on both while the *next* report carries `86 01 01`.
- **A defect was found by this capture and fixed:** the reference client writes the whole RCB back
  when it subscribes, `DatSet` included, and the new re-binding path was treating that as a
  reconfiguration and bumping `ConfRev` on every subscription. Writing back the value that was read
  is now a no-op. `mms.iec61850.confrev` reading 1 rather than 2 in the capture above is that fix.

**Multi-client RCB reservation, driven.** Two instances of the reference stack's reporting client
were pointed at one report control block at the same time, multiplexed onto one `Server` by
round-robin with `Server.peer` set from the socket:

- the first took `Resv` and became `Owner`;
- the **second's** `setRCBValues` came back `object-access-denied` and its own stack printed
  `setRCBValues service error!`; the server counted exactly one refused write;
- a **third** association — the reference stack's generic MMS browser — read the whole URCB and
  printed `{Events1,true,true,simpleIOGenericIO/LLN0$Events,1,0111100010,50,2,011001,0,false,`
  `c0a80101}`: twelve members, `RptEna` and `Resv` both true, and `Owner` = the four octets of the
  first client's association id. On the wire those two attributes are `83 01 01` and
  `89 04 C0 A8 01 01`, which are the shapes pinned as goldens in `reporting.zig`;
- rawshark read the same frame as `mms.boolean` = True, True, False (`RptEna`, `Resv`, `GI`) and
  `mms.unsigned` = 1, 50, 2, 0 (`ConfRev`, `BufTm`, `SqNum`, `IntgPd`), with no malformed frames in
  the 34-frame capture.

**SCL emission.** 45 real configuration files (the reference stack's shipped `.icd`/`.cid`/`.scd`)
were parsed, emitted and re-parsed:

- **44 round-trip to an identical name space** (the 45th is an `.scd` whose data sets reach into
  another IED and does not resolve in the first place, so there is nothing to compare);
- every emission is well-formed per `xmllint`;
- every emission was fed to the reference stack's own **SCL model generator**: **none was
  rejected**, and **36 of the 44** produce a byte-identical generated C model (it was 31 before
  `<Log>` elements were parsed and emitted; the two numbers come from the same harness — generate
  from the original and from the emission into the same output name, and compare both files
  ignoring the "automatically generated from" banner line). The 8 that still differ do so for three
  reasons:
  - **`<SampledValueControl>`** (3 files) — the generator emits an `SVControlBlock` and its
    `PhyComAddress` from the `SMV` binding in the `Communication` section; `scl.zig` parses neither.
  - **`<Services>`** (2 files) — the generator folds its `ReportSettings` into the RCB's trigger
    word (`88` where ours has `24`).
  - **the original is rejected and ours is not** (2 files, both `sampleModel_errors.icd`) — the
    generator produces nothing from the source and a full model from our emission, which is a
    difference in our favour rather than a loss.
  - one file (`sv.icd`) differs in a single generated constant, also SV-related.
- Two defects were found *by* that generator and fixed: `LogControl/@logName` is mandatory and must
  be written even when empty, and **`OptFields/@bufOvfl` defaults to `true`** in the schema — this
  module's parser had been defaulting it to false, which silently produced a different RCB from
  every other tool reading the same file.
- The writer emits an optional attribute **only when it differs from the schema default**, and keeps
  the **source document's namespace**, because a reader picks which edition's defaults to apply from
  that URI. Both were learned from the generator disagreeing.

### What is self-derived

- **Everything the oracle's example model does not contain.** The captured IED is
  `libiec61850`'s shipped example (`simpleIOGenericIO`, `testComplexArray`), so nothing a real IED
  *sends* exercises the segmented-report path. The path is now driven the other way instead — our
  server splitting a report to a third-party client, described under "Segmentation" below — but the
  reference clients still never *ask* for `OptFlds.segmentation` or `data_reference`; this server's
  own configuration turns them on. Both are cross-tested encoder-against-decoder over **all 512
  combinations** of the nine defined `OptFlds` bits.
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
- **The two spellings of `TimeOfEntry`.** `scl.Options.brcb_attributes` exists because
  implementations disagree (`TimeOfEntry` vs `TimeofEntry`); the RCB emitter answers to both.
- **`GetJournalStatus`.** IEC 61850's own `GetLogStatusValues` is served by *reading the LCB*
  (`OldEntr`/`NewEntr`/`OldEntrTm`/`NewEntrTm`), and that path is driven against a third party. The
  MMS `[68]` service itself is encoded from the published ISO 9506 layout and round-tripped against
  this module's own decoder — **no peer was observed sending it**, and no reference client offers it.
- **The `BufOvfl` and `EntryID` resume paths of a BRCB** are driven end to end against this module's
  own client and unit-tested against a bounded buffer, but the reference clients never disable a
  BRCB long enough to overrun one, so the overflow flag was never observed arriving at a third party.
- **The `Owner` octet string's *meaning*.** IEC 61850-7-2 says only that `Owner` identifies the
  client that owns the block; it does not fix the encoding. This module puts the four big-endian
  octets of the caller's association id in it, which renders as an IPv4 address when the caller uses
  one — and that is what every stack observed here does — but the convention is the caller's, not
  the standard's. An **unowned** block emits a zero-length octet string rather than four zero
  octets, which is this module's own choice: "nobody" and "0.0.0.0" are different answers.
- **The multi-association `Server`.** `Server.peer` is the seam a front end sets per frame, and the
  live two-client test drives it that way — but one `Server` object still holds **one**
  presentation-context table and one negotiated PDU size for all of them. That works in the live
  run only because both peers propose identical context ids. A production front end gives each
  association its own view; this is a simulator.
- **The `ResvTms` readings.** That a BRCB reservation with `ResvTms > 0` outlives the association by
  that many seconds, that `-1` holds it until released, and that the SGCB's `ResvTms` is an
  *inactivity* timeout are all readings of IEC 61850-7-2 that no peer confirmed: no reference client
  writes either attribute. They are unit-tested against an injected clock and stated here as
  readings.
- **The SCL `Substation` section is skipped**, not parsed: `Scl.has_substation` records that it was
  there (which is what `kind()` uses) and nothing more. Single-line diagrams are a configuration-tool
  concern, not a client's.

### Fuzz + hostile input

`std.testing.fuzz` sweeps, all asserting "typed error or valid result, never a panic and never a
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
- an arbitrary `Data` value written into every RCB attribute of both kinds, then a `tick` and an
  `emitNext` on whatever state that left behind;
- an arbitrary `Data` value written into every SGCB attribute, then `SetEditSGValue`,
  `ConfirmEditSGValues`, `GetSGValues` and `GetEditSGValue` on the wreckage;
- arbitrary bytes through `ReadJournal`'s request and response decoders and `GetJournalStatus`'s,
  walking every journal entry and every variable inside it.

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

For the new segmentation, re-binding, reservation and journal-deletion halves: a segment whose
`SubSeqNum` **skips** (`error.SegmentOutOfOrder`, and so is a continuation with nothing open), a
segment whose `EntryID`, `RptID`, `DatSet` or `SqNum` disagrees with the one that opened the report
(`error.SegmentMismatch` rather than a spliced report that never existed), a reassembly that
**never completes** (bounded by the caller's slot table and arena — `error.ReassemblyBufferTooSmall`,
and the next `SubSeqNum == 0` reclaims the storage), a data-set member larger than a whole segment
(`error.SegmentTooSmall`, never a truncated value), a `DatSet` write naming a data set that does not
resolve (refused, and the binding does not move), a `DatSet` write while `RptEna` is set (refused,
and `ConfRev` does not move), a `DatSet` write through a `Source` with no resolver at all (refused
rather than pretending), a `ResvTms` below `-1`, a reservation held by an association that has
**dropped** (kept for a BRCB, released for a URCB, expired by `tick`), an SGCB edit that **expires
mid-sequence** (the confirm, the next edit and the `SE` read that follow it are all refused), and a
log deletion **spanning the purge boundary** (deletes what survived and reports that count, never an
error) or reaching past the far end. Two more fuzz sweeps cover them: an arbitrary sequence of
segments fed to the reassembler with random drops, and arbitrary bytes through both deletion
services' decoders followed by a real deletion.

For the older server-side halves specifically: a BRCB enabled with a `DatSet` that does not resolve
(reports nothing rather than faulting), an `OptFlds` combination the encoder does not support (there
is none — all 512 are cross-tested against the decoder — but an inclusion index outside the data set
and a data set wider than the inclusion bit string are both typed errors), an `EntryID` resume point
that has fallen out of the bounded buffer (`error.EntryIdNotFound`, and `0` still resolves to
"whatever is left"), a log query that spans a purge (returns what survived, never an error), an
entry whose captured values do not fit its slot (`error.EntryTooLarge`, never a truncated report), a
`ConfirmEditSGValues` with no preceding `SelectEditSG` and one with a selection but nothing edited
(both refused, over the wire as well as in-process), a setting value larger than its slot, a
`Setting` table that does not match `NumOfSG`, an SGCB edit taken by a second client, a
reconfiguration of an enabled RCB, and an SCL emission of a model with a **cyclic type reference**
(direct, two-step and through an `SDO`) — refused with `error.CyclicType` before an octet is
written, and terminating rather than looping even with the check disabled.

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
- **The `Server` is a simulator, not an IED.** It now enforces the control model, reports, logs and
  switches setting groups — which makes it *more* convincing on a wire, not more trustworthy. There
  is still no SCL model loader, no access control and no file system. Do not put it on a network
  where something might mistake it for real equipment.
- **A report is an attack surface pointing outwards.** An enabled BRCB retains data for a client
  that may never come back; the buffer is bounded by the caller's storage precisely so that a
  disappeared client cannot be turned into unbounded memory growth. Size it deliberately.

## Deferred

Honest list of what a full IEC 61850 implementation has and this one does not. IEC 61850 is
enormous; this module ships MMS read/write/browse, the control model, SCL parsing and resolution,
and GOOSE publish/subscribe, each done properly.

**Driven end to end (client and server, live against a third party):** association, `GetNameList`
at all three scopes, `Read` and `Write` over named variables and named variable lists,
`GetNamedVariableListAttributes` answered by this server, RCB read / enable / general interrogation
/ disable, `InformationReport` reception, the whole **control model** (`ctlModel`/`sboTimeout`
reads, the `SBO` read and the `SBOw` write, `Oper` under all four models, `CommandTermination` in
both directions, `LastApplError` received from a real IED, `GetVariableAccessAttributes` on a
control object answered to a real client's satisfaction), and — new — the whole **server-side
reporting engine** (a third-party client subscribing to our URCB and receiving data-change,
integrity and general-interrogation reports with the right per-member reason codes), **report
segmentation** (a third-party client receiving a report split across two `InformationReport`s and
printing all twelve of its members), **RCB reservation** (`Resv`, `Owner` and the refusal, with two
third-party clients contending for one block), **logging**
(`LogEna` written, the LCB read, `ReadJournal` answered with entries a third-party client decoded),
and **setting groups and the BRCB** read back by a third-party MMS browser.

**Driven against a real IED's own name space (not against a peer, but against ground truth):** the
whole SCL parse and type resolution — twelve configuration files, 3,273 names, exact in both
directions against the `GetNameList` of the IED each file configures.

**Codec-only (encoded and decoded, unit-tested, never driven against a peer):** `Identify`,
`GetVariableAccessAttributes` for anything that is **not** a control object (the general type tree is
decoded but this server only describes control objects), `DefineNamedVariableList`,
`DeleteNamedVariableList`, all four file services' *responses*, **`GetJournalStatus`**, segmented
reports, `data_reference` reports, `Owner` on an RCB, SV in both directions, the alternate-access
sub-specification (preserved verbatim, not interpreted), `operTm` on a control command, a `ctlVal`
that is not a `BOOLEAN`, and every `AddCause` other than `Object-not-selected` (produced and
consumed by this module's own two halves, never observed from a third party — no oracle model
exposes an interlock or a synchrocheck).

Partly implemented, with the boundary stated:

- **Emitting SCL** now exists (`sclwrite.zig`) and is round-tripped through the resolver over 44
  real files, but it is a **model writer, not an editor for someone else's document**. It emits what
  `scl.zig` parses and nothing more, so a document with a `Substation` section, `Services`,
  `SampledValueControl`, `Inputs`/`ExtRef`, `Private`/`Text` elements or a `desc` on
  an `LN`/`ReportControl` loses them — `emitParsed` refuses outright when `has_substation` is set
  unless the caller passes `allow_lossy`. An empty attribute and an absent one are indistinguishable
  once parsed, so the writer picks whichever form every consumer accepts. Attribute *order* and
  whitespace are the writer's, not the source's; `LN0` is moved to the front because the schema
  sequences it there.
- **The server-side reporting engine** implements the trigger set, `BufTm` coalescing, the integrity
  period, general interrogation, the bounded buffered-report guarantee with `EntryID` resume and
  `BufOvfl`, the whole RCB attribute surface, **report segmentation**, **runtime `DatSet`
  re-binding** and **multi-client reservation** (`Resv`, `ResvTms`, `Owner`). What it does not do is
  split one MMS PDU across several COTP TPDUs on the *outbound* (response) side: a class-0 TPDU is
  at most 8192 octets, so a *read* response larger than the negotiated TPDU size is a
  `BufferTooSmall` rather than a fragmented one. **Inbound** requests are the other direction:
  `Server.handle` reassembles a segmented request via `cotp.Reassembler` (`reasm_buf`/`reasm_len`,
  mirroring `client.zig`'s identical receive-side reassembly) before decoding it — a peer that
  splits a large `Write` across several `DT` TPDUs is served normally, not refused.
  That ceiling is also what makes the segmentation budget honest — `Server.reportSegmentBudget` is
  the smaller of the client's `localDetailCalling` and the negotiated TPDU size, less the
  session/presentation envelope. `Owner` is part of the RCB *structure* only when `include_owner`
  is set, because a client reading a structure of the wrong shape mis-assigns every field after the
  change; it is readable by name either way.
- **Logging** implements the LCB, a bounded circular store, `ReadJournal` with `listOfVariables`
  filtering, `GetJournalStatus`, and the deletion services `InitializeJournal` (delete the entries a
  `limitingTime` / `limitingEntry` covers, answering with the count) and `DeleteJournal` (refused:
  the journals are part of the caller's static model, exactly as a configured IED's are). A
  deletion that reaches past what the store has already purged deletes what survives and reports
  that count — spanning the purge boundary is not an error. It still does not implement per-entry
  `originatingApplication`: an empty `ApplicationReference` is emitted, which is what the reference
  IED does.
- **Setting groups** implement all six services, the edit-then-confirm invariant and `ResvTms`.
  `ResvTms` is read as an **inactivity** timeout: an edit selection that goes quiet for that many
  seconds is taken back on `tick`, and every `SetEditSGValue` restarts it, so a slow edit is never
  interrupted while an abandoned one cannot hold the setting groups for ever. `ResvTms = 0`, the
  default, is the old behaviour: the selection is released when the association drops and not
  before. The attribute is part of the SGCB structure only when `include_resv_tms` is set.

Not implemented at all:

- **The SCL `Substation` section** (single-line diagram, voltage levels, bays, conducting equipment,
  `LNode` bindings) and `Private`/`Text` elements. `Scl.has_substation` records that it was present
  and nothing else. Also unparsed, and therefore also not emitted: `Services` capabilities,
  `SampledValueControl` and `Inputs`/`ExtRef` (the subscription bindings edition 2 uses). Those are
  what is left of the reason 8 of the 44 emitted files produce a generated model that differs from
  the original's; `<Log>` elements used to be on this list and are now parsed and emitted.
- **Validating an emitted document against the IEC 61850-6 XSD.** The schema is not redistributable
  and is not present here; validation is `xmllint` well-formedness plus acceptance by a third-party
  SCL model generator. That is a weaker claim than schema validity and is stated as such.
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
both (client + server, publisher + subscriber) · single_owner` + deps: `xml` (SCL parsing, and the
round-trip check on emission; every other file is std-only and allocation-free) — canonical source
is `pub const meta` in src/root.zig.

The suite runs offline except for a handful of live, env-gated tests (each printing `SKIPPED: …`
and passing when no peer is present).

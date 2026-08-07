# s7comm — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## Design & invariants

Six allocation-free layers, mirroring the protocol's own stacking (TPKT → COTP → S7comm →
Read/Write Var or Userdata). Every wire struct uses explicit shifts in its encode/decode
rather than a `packed struct`, so the octet layout never depends on Zig's bitfield-packing
rules.

- **`tpkt` (RFC 1006 §6).** The length field counts **the header itself**, so a decoder that
  treats it as a payload length desynchronises the stream by four octets and never recovers.
  `decode` therefore returns `total_len` separately from `payload`, and `peekLength` exists so
  a socket adapter can read exactly one packet without buffering blind. `Framer` compacts on
  `feed`, refuses a packet larger than its own storage (rather than waiting forever for octets
  that will never fit) and returns `null` until a whole packet is present.
- **`cotp` (ISO 8073 class 0).** `LI` counts the octets after itself **excluding user data**,
  which is what puts the S7 PDU at `1 + LI`. A `DT` with `LI != 2` is refused rather than
  guessed at, because in class 0 that value is fixed and a different one means the framing is
  already wrong. Transport classes other than 0 are refused at the CR/CC.

  **The TPDU code is a full octet except on `CR` and `CC`.** RFC 905 §13.2.2.2 names exactly four
  codes whose bits 4-1 carry a CDT — `1110 xxxx` CR, `1101 xxxx` CC, `0101 xxxx` RJ, `0110 xxxx`
  AK — and closes with "only those codes defined in 13.1 are valid"; Table 8 spells the rest as
  full octets (`DR 1000 0000`, `DC 1100 0000`, `DT 1111 0000`, `ER 0111 0000`), which 13.7.3 a)
  repeats for `DT`. A non-zero low nibble on those four is therefore `UnknownTpduCode`, not a
  `DT` with a nibble to be dropped. Dispatching on the high nibble alone made sixteen distinct
  octets decode as one and re-encode as `0xF0` — an information-losing accept, and on an OT
  segment a DPI/IDS evasion primitive, because a monitor keyed on the literal `02 F0 80` sees
  nothing while the stack behind it processes `02 F7 80` as data.

  **The same applies to bits 4 and 3 of a CR/CC's class-and-option octet.**
  §13.3.3 e) tabulates that nibble as bit 4 "0 always", bit 3 "0 always",
  bit 2 extended formats, bit 1 no explicit flow control — and NOTE 2 adds
  that in class 0 all four "are always zero and have no meaning". Bits 2 and
  1 are modelled and round-trip; bits 4 and 3 had nowhere to go, so four
  octets decoded as one and `encodeConnectVerbatim` emitted the one. They are
  now `UnsupportedClass`, which makes the decode of that octet a bijection.

  Unknown variable-part
  parameters survive a decode (the raw `variable_part` is kept), which is what makes
  `encodeConnectVerbatim` byte-exact for peers that order parameters differently — one of the
  two captured stacks emits `src, dst, size` and the other `size, src, dst`, and both must
  round-trip.
- **Rack and slot are a `Tsap`, not two fields.** There is no rack or slot anywhere in the S7
  protocol; the addressing everyone means by *rack 0, slot 2* is the destination TSAP
  `{connection type, rack * 0x20 + slot}`. This is modelled explicitly because a wrong slot
  produces **no error message at the S7 layer at all** — the CPU refuses the transport
  connection, or accepts it and fails every subsequent read. `rackSlot` takes a `u3` rack and a
  `u5` slot so an out-of-range value is a compile-time impossibility rather than a silently
  truncated octet.
- **`s7`: the header is 10 octets for a Job or Userdata and 12 for an Ack or Ack-Data.** That
  branch (`Rosctr.hasErrorField`) is the single most load-bearing line in the module: a hard-coded
  10 reads every reply's parameters two octets early and a hard-coded 12 does the same to every
  request. `decode` additionally requires `parameter_length + data_length` to account for
  **exactly** the octets present — in a protocol with no per-PDU checksum, a length disagreement
  is the only signal that framing has gone wrong, so neither a short nor a long PDU is accepted.
  `encode` derives the two length fields from the slices it is given and never from the caller's
  struct, so an inconsistent header cannot be produced.
- **The negotiated PDU length is a first-class property.** `Setup communication` is exchanged
  before anything else and the PLC is free to answer with less than was asked for (240 and 480
  are both common). The client stores `@min(agreed, requested)` — a peer must not be able to
  *raise* the ceiling, because every buffer downstream is sized from this number — and
  `readBytes`/`writeBytes` split transfers to fit it while the single-item entry points refuse a
  transfer that would not, rather than emitting a PDU the peer will silently drop. The budgets
  (`maxReadPayload = pdu - 18`, `maxWritePayload = pdu - 28`, `maxRequestItems = (pdu - 12) / 12`)
  are derived from the frame layouts and confirmed against a captured 600-octet read that the
  reference client split at exactly 462 + 138 under a 480-octet PDU.
- **The item address is a bit address.** `DB1.DBW20` is wire address `20 * 8 = 160`. This is the
  classic S7 bug and it does not fail loudly — it reads the wrong eighth of the DB, and byte 0
  (the one everybody tests with) is 0 either way, so it survives the first test. `Item.at` takes
  a byte offset and a bit index and does the shift; `byteOffset`/`bitOffset` undo it. Timers and
  counters are the exception: there the three octets count **elements**, so `Area.addressesElements`
  branches and a bit index on one of them is a typed error.
- **The data block's length unit depends on the transport size.** `bit`, `byte_word_dword` and
  `int` count **bits**; `dint`, `real` and `octet_string` count **octets**. A decoder that assumes
  one unit is off by a factor of eight. `encodeLength`/`decodeLength` own that rule in one place,
  and a bit-counted length that is neither a whole octet nor a single bit is a typed error rather
  than a silent truncation.
- **Padding and failed items are the two shapes a data-block walker must get right.** Every item
  except the last is padded to an even length, and the pad octet's value is *not* specified —
  the reference stack emitted uninitialised memory (`0xBA`) there in the capture, which is why it
  is skipped and never validated. An item whose return code is not `success` is **exactly its
  four header octets**: no payload, no padding, whatever its length field claims. A reply that
  mixes a failed and a successful item therefore contains items of two different shapes, which is
  the case a naive parser walks off the end of; `DataItemIterator` bounds every step against the
  block it was given rather than against the parameter block's item count, so a peer that lies
  about the count cannot steer it out of bounds.
- **Request data blocks are not reply data blocks.** In a Write Var *request* the return-code
  octet is `0x00` (reserved) and the payload follows regardless; only in a *reply* does a
  non-success code mean "no payload". `DataItemIterator.initRequest` exists for exactly that,
  and getting it wrong makes a responder drop every value it was asked to write — which is how
  this was found.
- **`userdata`.** The Userdata parameter block is a different shape from a Job's: a fixed
  `0x000112` head, a length octet that says 4 for a request and 8 for a response (checked, not
  assumed), a packed `type|group` octet and, on a response, the data-unit reference, the
  `last data unit` flag and a 16-bit error code.
- **`address`.** A `.<bit>` suffix is legal only where a bit can be addressed and only for bits
  0..7 — `M10.8` is a typo, not "byte 11 bit 0", and is refused rather than normalised. `DB1.DBX0`
  without a bit is likewise refused as ambiguous, and DB 0 is refused because DB numbering starts
  at 1.
- **`server`.** `Responder` is a pure function from one packet to one packet over caller-owned
  byte slices — no program execution, no cycle, no retentive-memory semantics. It reproduces the
  reference CPU's *exact* replies, down to the `0x0004` length field a failed item carries and
  the `ff 03 0001 01` shape of a single-bit read.

Concurrency: `.single_owner` — one `Client`/`Responder` owns one connection's buffers and PDU
reference; nothing is shared or global, and any threading is the caller's.

Error policy: every decode entry point (`tpkt.decode`, `tpkt.Framer.next`, `cotp.decode`,
`s7.decodeHeader`, `s7.decode`, `items.Item.decode`, `items.DataItemIterator.next`,
`vars.decodeRequest`, `vars.decodeReply`, `userdata.Param.decode`, `userdata.SzlResponse.decode`,
`address.parse`, `Responder.handle`) returns a typed error on malformed input. Nothing panics,
allocates or loops unboundedly.

## Verification

### What is third-party-validated

The strongest evidence here is not a hand-written vector — it is **real traffic between two
independent implementations that are not this module**, plus **live round trips in both
directions**.

**Oracles used**, both installed in throwaway virtualenvs and driven **as black boxes only** — to
generate wire traffic, to act as a live peer, and to be diffed against. No third-party source was
read as a design reference. Under CONVENTIONS §5 that is a test oracle, not a design reference, so
it needs no `/NOTICE` entry — the same status as diffing against `tar` or `nft`.

1. **The `snap7` C library** (Davide Nardella), reached through `python-snap7` 2.0.2, which ships
   the compiled `libsnap7.so` in its wheel. Both its client and its virtual-CPU server were used.
   This is the reference S7 implementation the whole field is checked against.
2. **A second, independently written pure-Python S7 stack** (`python-snap7` 3.1.0, which is a
   native re-implementation rather than a binding). Only its connection handshake and its COTP
   disconnect are kept as goldens, because it orders the COTP parameters differently from the C
   stack and appends a stray octet to its `DR` — two differences worth pinning.

Concretely:

1. **113 byte-exact captured goldens** (`goldens.zig`). A snap7 client was pointed at a snap7
   server through a TPKT-aware recording TCP proxy, and every packet that crossed the wire was
   logged as hex. Four assertions run over the whole table:
   - every packet decodes (TPKT, COTP, and for a `DT` also the S7 PDU, with the parameter and data
     lengths accounting for exactly the octets present);
   - every packet **re-encodes to the identical octets** — the S7 PDU is rebuilt from its decoded
     header and blocks, and the CR/CC from its decoded variable part;
   - every Read/Write Var request's parameter block is rebuilt from its **decoded items** through
     `vars.encodeRequest`, so the item encoder is what is being checked and not a memcpy;
   - a coverage assertion fails if the table ever stops containing a CR, a CC, a DR, a Setup, a
     Read Var, a Write Var, a Userdata request, a per-item error, a multi-item request, a PLC
     control request, the six areas (DB, M, I, Q, T, C) and the seven transport sizes (bit, byte,
     word, dword, real, counter, timer) — so the goldens cannot silently rot.

   Coverage of the capture: COTP connect at rack 0 slot 1 **and rack 1 slot 2** (TSAP `0x0122`),
   Setup at 480 octets in both directions; byte/word/dword/real/counter/timer reads and writes;
   single-bit reads and writes in DB and M; reads of DB, M, I (PE), Q (PA), T and C; a three-item
   multi-var read; a three-item read with **odd payload lengths (1, 3, 2) so the padding is
   visible**; a two-item multi-var write with odd lengths; a two-item read where one item fails and
   one succeeds; single-item failures for a missing DB (`0x0A`) and an out-of-range address
   (`0x05`); a 600-octet read **split at the 480-octet PDU boundary into 462 + 138**; `Read SZL`
   for `0x0011`, `0x001C`, `0x0132` and `0x0424`; and `PLC stop`, `warm restart` and `cold
   restart` with their `P_PROGRAM` parameter blocks.

2. **The responder's replies are byte-compared against the recorded CPU's.** Replaying the captured
   client requests through `Responder.handle` reproduces the snap7 server's answers octet for octet
   for: the `Setup communication` acknowledgement, a DB write, a DB read, a read of a DB that does
   not exist, and a read past the end of a DB that does.

3. **Live round trip, our client → a real snap7 server** (`root.zig`, gated on `S7COMM_TEST_SERVER`).
   Against a live snap7 virtual CPU on `127.0.0.1:1602`, rack 0 slot 1, the run performed: COTP
   connect and Setup (negotiated PDU 480); an 8-octet DB write and read-back compared byte for byte;
   a single-bit write and read-back in both polarities; a **600-octet write and read-back that
   crossed the PDU boundary in both directions**; a two-item multi-var read in one PDU where the
   second item named a DB that does not exist and came back with a real per-item
   `object_does_not_exist`; `Read SZL 0x0011` returning 4 records; and `cpuStatus()` returning
   `run`. Printed output:
   `live S7: pdu=480 rack=0 slot=1 db_rw=ok bit_rw=ok multi_item_err=object_does_not_exist
   split=true szl0011_records=4 cpu=run`

4. **Live round trip, a real snap7 client → our responder** (`root.zig`, gated on
   `S7COMM_TEST_LISTEN`). A live snap7 client connected to our `Responder` on `127.0.0.1:1702`,
   negotiated a 480-octet PDU, wrote and read back `11223344` in DB1, wrote and read back `beef` in
   the M area, ran a two-item multi-var read that returned both values correctly, read the CPU
   state (`S7CpuStatusRun`, i.e. our synthesised SZL `0x0424` was accepted by a third-party
   decoder), and got a correct `CPU : Item not available` for DB 77. Our side printed
   `live S7 responder: reads=5 writes=2 userdata=1 db1[0]=0xA5`.

Both live tests passed in Debug and in `--release=fast`, and both print `SKIPPED: …` and pass when
no peer is present.

### What is self-derived

- **The `last data unit` polarity.** Every complete single-PDU response in the capture carried
  `0x00`, so `0x00` is taken to mean "this is the last one" and `0x01` "more follow". A **fragmented**
  response was never produced by the oracle, so the `0x01` case is unverified against a third party.
- **Transport sizes `int` (5) and `dint` (6) in the data block.** Their bit-versus-octet length
  units follow the documented rule (3/4/5 count bits, 6/7/9 count octets); the capture only
  exercised 3, 4, 7 and 9, all of which match.
- **Areas beyond the six that were exercised** — `instance_db` (0x85), `local` (0x86),
  `previous_local` (0x87), `direct_peripheral` (0x80), `system_info` (0x03), `system_flags` (0x05),
  `analog_inputs`/`analog_outputs` (0x06/0x07) — and **transport sizes beyond the seven** (char,
  int, dint, date, tod, time, s5time, dt, the IEC timers/counters) are encode/decode round-trip
  tested against their documented codes and widths, not against third-party bytes.
- **TSAP forms other than rack/slot.** `Tsap.raw` exists for CPUs configured with e.g. `0x1000`,
  but no such peer was available; only the rack/slot form was exercised live.
- **The COTP `ER` TPDU and non-zero TPDU numbers.** Neither oracle emitted an `ER` or a `DT` with
  the EOT bit clear; both are decoded from the documented layout and unit-tested, not captured.
- **`tshark` is not installed in this environment**, so the `s7comm` dissector cross-check named in
  the task was not run. It was not needed: the goldens came from a real capture between two
  independent stacks rather than being hand-derived, and the coverage assertion pins what they
  contain.
- **The oracle is a *virtual* CPU, not real hardware.** No S7-300/400/1200/1500 was available. The
  snap7 server implements the same wire protocol and reports itself as a `CPU 315-2 PN/DP`, but
  quirks specific to real firmware (S7-1500 access levels, optimised-block symbolic addressing,
  connection-resource exhaustion) are by definition not covered.

One divergence worth recording: the pure-Python stack sends a single-bit write with a length field
of **8** where the C stack sends **1**. Both decode here — `decodeLength` accepts a bit-counted
length of 1..8 for a single-bit transfer — and this module emits **1**, matching the C reference.

### Fuzz + hostile input

`std.testing.fuzz` sweeps, all asserting "typed error or valid result, never a panic and never a
hang":

- `tpkt.decode` over arbitrary bytes — anything that decodes must re-encode to the identical octets
  and its `total_len` must not exceed the input.
- `tpkt.Framer` fed arbitrary stream bytes in chunks, with a guard counter that fails the test if
  `next` ever returns a packet without consuming input (an infinite-loop bug).
- `cotp.decode` over arbitrary bytes — a CR/CC must re-encode verbatim, a DT must re-encode exactly,
  and anything that decodes as a `DT`/`DR`/`DC`/`ER` must have come from a code octet whose low
  nibble was zero. `DR`/`DC`/`ER` have no re-encoder, so that last assertion is the only octet-level
  check they get; it is what would have caught the `0xF7`-decodes-as-`DT` accept on the first sweep.
- `s7.decode` over arbitrary bytes — anything that decodes must re-encode to the identical octets.
- `items.Item.decode` and `items.DataItemIterator` over arbitrary bytes **and an arbitrary item
  count**, with a guard on both the iteration count and the consumed length.
- `vars.decodeRequest` plus full item iteration over arbitrary bytes.
- `userdata.Param.decode`, `userdata.DataBlock.decode` and `userdata.SzlResponse.decode` over
  arbitrary bytes, with the record accessor walked to exhaustion.
- `address.parse` over arbitrary bytes, with anything that parses required to build an encodable
  item.
- `Responder.handle` against real backing areas, driven by a **structure-aware** generator: the
  TPKT/COTP/S7 envelope is built rather than guessed, and the fuzzed fields are the ones the
  responder acts on — the S7ANY item descriptors (transport size, element count, DB number, area,
  address) and a Write Var data block whose declared length and actual payload are drawn
  independently. Arbitrary *packets* are covered by the raw-byte harnesses one layer down
  (`tpkt`, `cotp`, `s7`, `vars`, `items`); a harness that has to guess a four-layer envelope
  before it reaches `doRead` reaches it with probability ~0, which is how the zero-element-count
  read past the end of an area stayed invisible.

Explicit hostile-input tests (not fuzz) cover every case named in the task and more: a TPKT shorter
than its header, a bad version octet, a non-zero reserved octet, a length below the header size, a
**TPKT length that disagrees with the payload in both directions**, a packet larger than the
framer's storage; a **COTP length indicator pointing past the buffer**, an `LI` of zero, an unknown
TPDU code, **all sixteen low nibbles of each of `DT`/`DR`/`DC`/`ER`** (exactly one of which may
decode) and all sixteen credits of a `CR` (all of which must), all sixteen option
nibbles of a `CR`'s class octet (four of which must), transport class 4, a CR whose `LI` does not cover its fixed part, a `DT` with `LI != 2`,
a TSAP parameter of the wrong length, a TPDU-size parameter of the wrong length, a parameter whose
length runs off the end of the variable part and a dangling parameter code; an **S7 header whose
parameter and data lengths overflow the frame** (both singly and summed), trailing junk past the
announced body, a bad protocol id, an unknown ROSCTR, an Ack-Data that stops before its error
octets, a Setup with an unusable PDU length; an **item count that disagrees with the payload** in
both directions, a foreign syntax id (`0xB2`, S7-1200/1500 symbolic addressing), a bad variable-spec
marker, a bad specification length, a **length that contradicts its transport size**, a data-item
length that runs past its block and a truncated item header; a **read reply whose per-item return
code is an error while data is present** (the data must not be handed back), a mismatched PDU
reference, and a PLC-level error class; plus roughly thirty malformed address strings.

## S7CommPlus

S7CommPlus (protocol id `0x72`) is the S7-1200 / S7-1500 dialect. It rides on the **same** TPKT +
COTP class-0 transport as classic S7comm — the transport layers (`tpkt.zig`, `cotp.zig`,
`transport.zig`) are reused unchanged — but everything above the COTP `DT` is a different protocol:
a TLV object graph with a session, a per-PDU sequence number and a running integrity value, rather
than the `0x32` header with area/offset reads. It lives in a separate namespace (`root.s7plus`) so
the classic surface is entirely unaffected; the public API is purely additive.

### Design & invariants

- **`s7plus_value.zig` — the typed-value codec (the heart).** Every attribute is
  `<flags><datatype><body>`. The load-bearing subtlety is the integer encoding: `UDInt`/`ULInt`/
  `AID`/`DInt`/`LInt`/`Timespan` are a **base-128 big-endian VLQ**, most-significant group first,
  `0x80` continuation. For the signed forms the value is two's-complement over the `7*N`-bit field,
  so the sign is the top bit of the whole number — which, because the first group is most
  significant, is exactly bit `0x40` of the **first** octet. Decoders accumulate in `u128` so a full
  64-bit value (which needs ten groups) cannot overflow mid-decode, and an over-wide encoding is
  `error.VarIntTooLong`, never a wrap. Structs/arrays/variants nest, so **every walk carries a depth
  counter** (`max_depth = 32`) and array counts / blob lengths are capped (`max_elements`), turning a
  hostile deeply-nested or count-overrun blob into a typed error rather than a stack overflow or a
  multi-gigabyte loop.
- **`s7plus.zig` — the frame.** `0x72`, a PDU-type octet (Connect / Data / Data-with-integrity /
  Keep-alive), a 16-bit data length; then the data part; then, on a `data_fw3` PDU, the trailing
  integrity part; then, on any Data PDU, a **trailer** — a second `0x72` header form with a zero
  length that closes the PDU. `decode` requires the data length, the integrity region and the
  trailer to account for **exactly** the octets present (there is no per-PDU checksum, so a length
  disagreement is the only framing signal), and a Connect / Keep-alive with anything trailing its
  data is refused.
- **`s7plus_object.zig` — objects, session, integrity.** The Data-PDU inner header is
  `opcode(1) reserved(2) function(2) reserved(2) seqnum(2)`; the reserved fields are checked, not
  assumed. Objects are `0xa1 <relation-id><class-id> ( attribute | object )* 0xa2`, walked with an
  independent, stricter depth bound (`max_object_depth = 16`). The **session** carries three running
  values — the session id (assigned by the CPU at connect), the sequence number (client-incremented,
  echoed by the reply), and the **integrity id** (a running anti-replay value newer firmware checks).
  `Session.verifyIntegrity` enforces that a V3 PDU's id is **exactly** the expected next value and
  advances it; a repeated or stale id is `error.IntegrityReplay`. A V1/V2 session leaves it disabled.
- **`s7plus_path.zig` — symbolic addressing.** `"MotorData".Axis[2].Position` parses into a bounded
  component list; a quoted root is required, and every malformed form (unterminated quote, empty
  step, non-numeric / unterminated subscript, dangling dot, trailing garbage, overflow) is a typed
  error. `resolve` maps the root name to the CPU's relative object id against a caller-supplied table.

### What is validated — third-party-anchored vs self-derived

The honest bar here is **lower** than the classic layers, and stated as such:

- **No live peer.** snap7 — the reference the whole field checks against — implements classic
  S7comm **only**, so it cannot act as an S7CommPlus oracle. No S7-1200/1500 and no obtainable open
  S7CommPlus simulator were available. There is therefore **no interop test**, and none is faked.
- **No `s7comm-plus` dissector.** This environment's Wireshark 4.6.4 ships the classic `s7comm`
  dissector but **not** `s7comm-plus` — verified by inspecting `libwireshark.so.19` (it contains
  `s7comm.header.*` field strings and zero `s7comm-plus` / `s7commp` strings). `rawshark` therefore
  cannot field-decode a `0x72` body.
- **What `rawshark` *did* confirm (the envelope).** `rawshark` (Wireshark 4.6.4) was run over
  `s7plus_goldens.rawshark_envelope_frame`, a full `TPKT | COTP DT | 0x72 …` frame this module
  builds. It independently confirmed: `tpkt.length` == `24` (our TPKT total), `cotp.type` == `0x0f`
  (a class-0 DT), and `frame.protocols` == `tpkt:cotp:data` — i.e. the COTP payload boundary lands
  exactly where our `0x72` header begins. So the framing *around* S7CommPlus is third-party-validated;
  the `0x72` body is not.
- **Third-party-anchored:** the value/datatype codec and the header field layout follow the
  documented `s7comm-plus` wire structure directly, and the pinned value goldens (`udint_300`,
  `dint_neg1`, `real_one`, `wstring_hi`, …) are the closest thing to an external anchor — any
  re-implementation of the value codec must agree on those octets.
- **Self-derived:** the exact placement of the integrity part relative to the trailer, the trailer's
  own shape, the Data-PDU inner-header field order, the function codes, and the client/responder
  request/response *choreography*. All are internally consistent and round-trip exactly, but are a
  model, not a captured fact.
- **Firmware coverage.** The integrity id's **sequence semantics** (a strictly-monotonic running
  value the peer verifies) are modelled and enforced; the **keyed cryptographic derivation** of the
  id and its digest that the newest S7-1500 firmware uses is **not** — the digest is an opaque
  caller-supplied blob, not computed. This covers S7-1200 and S7-1500 up to the point where a signed
  integrity digest (and the associated session-key exchange / optional encryption) becomes mandatory.

### Codec-only vs driven

- **Codec-only (complete, exercised):** the value/datatype TLV codec, the frame framing, the object
  walker, the Data-PDU inner header, the symbolic path parser, and the session/sequence/integrity
  model.
- **Driven (over an in-memory wire, not a real PLC):** a client and responder exchange Connect,
  SetVariable and GetVariable through the actual codecs, including the integrity anti-replay check —
  a full round trip. This is a **self-consistent reference and a fleet-simulation target**, exactly
  like the classic `Responder`, **not** a validated S7-1200 driver.

### Fuzz + hostile input

`std.testing.fuzz` sweeps, all asserting "typed error or valid result, never a panic and never a
hang": the value walker over arbitrary bytes (bounded consumed length); the VLQ decoders (with a
re-encode/re-decode fixed-point check); the `0x72` frame decoder; the object walker; and the path
parser. Explicit hostile-input tests cover every case the task names: a `0x72` header whose length
disagrees, a TLV value whose length runs past the buffer, a struct nested past the depth bound, an
array count that overruns and one that is absurdly large, a datatype-flags octet with a reserved bit,
an integrity id that does not progress, and a symbolic path that does not resolve.

### Deferred (S7CommPlus)

- **Encryption / the newest-firmware integrity cryptography.** The keyed digest and the TLS-style
  session-key exchange the latest S7-1500 firmware layers on top are **out of scope**; only the
  integrity id's progression is modelled. This is stated plainly rather than half-implemented.
- **Cyclic subscriptions / notifications.** The `notification` opcode (`0x33`) is modelled in the
  header; the subscription machinery (SetVarSubStreamed and the unsolicited push flow) is not.
- **Symbolic sub-path resolution beyond the root.** `s7plus_path` resolves the root object id and
  carries the member/index steps verbatim; mapping a member *name* to its numeric id needs the
  object's browsed schema, which is not implemented (the client reads the root object).
- **Block upload / download, program transfer, and the `Explore` browse walk.** Function codes are
  named; the flows are not built.
- **Multi-variable batching** (`GetMultiVariables` / `SetMultiVariables`), keep-alive timers, and
  PDU-level retry / reconnection — as with the classic client, one request/reply per call, no timers.

## Threat model

S7comm is an **unauthenticated, unencrypted** protocol by design: anyone with a path to TCP port
102 can read and write any data block, and can stop the CPU. This module's job is therefore
robustness and containment, not confidentiality or integrity against an active attacker:

- Hostile or corrupt bytes from a misbehaving PLC, a hostile client or a MITM resolve to typed
  errors at every decode entry point.
- No allocation anywhere, and every buffer is caller-supplied and bounded, so a hostile peer cannot
  drive memory growth. The negotiated PDU length caps every transfer in both directions and is
  clamped so a peer cannot raise it.
- **The PLC control services are implemented and are dangerous.** `plcStop` halts a running machine
  (outputs go to their configured safe state, the process stops); `plcColdStart` clears retentive
  data and is destructive to process state, not merely to availability. There is no authentication
  step in front of them anywhere in the protocol — the "protection level" on an S7-300/400 is a
  CPU-side setting, not something a client proves. They are exposed because a diagnostic tool and a
  fleet simulator both need them and pretending they do not exist does not make a plant safer, but:
  nothing in this module calls them implicitly, each is spelled out in full at its call site, and
  the `Responder` **refuses them unless `allow_plc_control` is explicitly set**.
- **Deployments must put transport security under this** — a VPN, or an S7-1500 with its own
  connection mechanisms. This module implements none, and callers should hand the `Transport` seam
  an already-secured stream, exactly as the repo's BYO-TLS rule (CONVENTIONS §2) prescribes.
- The responder is a **simulator, not a PLC**: it executes no program and enforces no access level.
  Do not put it on a network where something might mistake it for real equipment.

## Deferred

Honest list of what a full S7 implementation has and this one does not:

- **Block upload and download** (functions `0x1A`–`0x1F`: request download, download block, download
  ended, start upload, upload, end upload). Not implemented at all — the function codes are named in
  `s7.Function` and nothing more. These are the genuinely dangerous ones (they replace the program a
  machine is running) and they need a block-format model (MC7 headers, block types OB/FB/FC/DB/SDB)
  that is a project of its own.
- **Symbolic addressing over *classic* S7comm** (syntax id `0xB2`). In the `0x32` protocol only
  `S7ANY` (`0x10`) is built and decoded; a `0xB2` item is `error.UnsupportedSyntaxId`. The
  S7-1200/1500 symbolic world is instead handled by the **S7CommPlus** (`0x72`) layer — see
  "S7CommPlus" below — which is the protocol those CPUs actually speak for optimised-block access.
- **Fragmented (multi-PDU) SZL responses.** `readSzl` returns the first PDU and reports
  `partial = true` when the CPU said more follow; the continuation exchange is not implemented,
  because no oracle here would produce one and guessing the sequencing would be worse than saying so.
- **Cyclic services** (function group 2: subscribe to a variable and receive unsolicited push PDUs).
  The Userdata sub-header models the `push` message type, but there is no subscription machinery.
- **Security / protection level** (function group 5): password login (`SetSessionPassword`), reading
  the protection level from SZL `0x0232`. Not implemented.
- **Time-of-day services** (function group 7): read and set the CPU clock.
- **Block listing and block info** (function group 3: `ListBlocks`, `ListBlocksOfType`, `GetBlockInfo`).
- **PDU-level retry, reconnection and keepalive.** The client performs one request/reply exchange per
  call and surfaces a transport failure; a production deployment wires reconnection into its own
  supervisor. There is no timer anywhere in this module.
- **Multiple concurrent outstanding requests.** `Setup communication` negotiates `max AmQ` in both
  directions and this client always uses 1, which is what every S7 driver in practice does; the PDU
  reference is incremented per request and the reply must echo it.
- **`ISO-on-TCP` over anything but TCP** (MPI, Profibus, the `libnodave` serial paths). Out of scope.
- **`tshark` cross-check** — not run (no `tshark` in this environment); see "What is self-derived".

## Status

`gap · any (pure codecs + client logic + responder; only the optional TcpTransport touches
std.Io.net) · both (client + responder) · single_owner` + deps: none (std only) — canonical source
is `pub const meta` in src/root.zig.

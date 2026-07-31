# enip — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## Design & invariants

Seven allocation-free layers, mirroring the protocol's own stacking
(encapsulation → CPF → CIP Message Router → Connection Manager → the Logix tag
services). Every wire struct uses explicit shifts and `std.mem.readInt`/
`writeInt` in its encode/decode rather than a `packed struct`, so the octet
layout never depends on Zig's bitfield-packing rules.

- **`encap` (Vol 2 ch. 2).** The length field counts the data **after** the
  24-octet header. It must account for *exactly* the octets present — this
  protocol has no checksum, so a length disagreement is the only signal that
  framing has gone wrong, and neither a short nor a long message is accepted;
  `decodePrefix` exists for the framer, which legitimately has the next message
  behind this one. `options` is *checked* to be zero rather than ignored: Vol 2
  §2-3.6 requires senders to zero it and receivers to reject anything else, and
  being strict is what stops a crafted message steering a future extension.
  `Framer` compacts on `feed`, refuses a message larger than its own storage
  (rather than waiting forever for octets that will never fit) and returns
  `null` until a whole message is present.

  **The `sockaddr_in` inside the identity and sockaddr items is network byte
  order in the middle of a little-endian message.** It is the single most
  common decoding mistake in this protocol and it does not fail loudly — port
  44818 read little-endian is 4783, which looks like a plausible port. It is
  owned in one place (`SocketAddress`) and bridged to `netaddr.Ip` there.

  **The `ListServices` name is not a fixed 16 octets.** The spec draws it that
  way; the reference target used for the goldens emits `"Communications\0"` —
  fifteen — and stops. The name is therefore "whatever is left in the item",
  which round-trips both shapes. A spec-literal decoder rejects real traffic.
- **`cpf`.** The structure is trivial and the rules over it are where
  implementations go wrong, so the rules are code: `validateDataOrder` requires
  at least two items, an address item first and a data item second, and refuses
  a connected address paired with unconnected data (or the reverse). Every walk
  bounds itself against the buffer rather than against the declared item count,
  so a peer that lies about the count cannot steer it out of bounds, and a
  declared count larger than the caller's item storage is an error rather than
  a silent truncation.

  **`SendRRData`/`SendUnitData` prefix the item list with a four-octet
  interface handle and a two-octet timeout; `ListIdentity` and friends do
  not.** Mixing those up shifts every item by six octets, which is why the
  envelope is a separate entry point (`decodeEnvelope`) and not a flag.

  **A connected data item begins with a two-octet sequence count that belongs
  to the item, not to CIP.** Handing it on to a CIP decoder shifts the service
  code by two and produces confident nonsense.
- **`epath` (Vol 1 App. C).** Four rules carry almost all of the bugs, and each
  is enforced rather than assumed: the path size is in **words** (so `words()`
  refuses an odd path instead of rounding); a 16/32-bit logical segment carries
  a pad octet in a *padded* path and not in a *packed* one (`padded` is an
  explicit parameter on both the iterator and the builder, never inferred); an
  ANSI Extended Symbol segment pads to even and **the pad is not part of the
  name** (`91 05 "SCADA" 00` is a five-character name); and array element
  indices are **Member ID** segments (`0x28`/`0x29`/`0x2A`), not attribute or
  instance segments.

  The decoded `Logical.format` is preserved so a re-encode is byte-exact: a
  peer may write instance 1 as a 16-bit segment even though 8 bits would do,
  and normalising it would break the goldens' re-encode assertion. A padded
  segment whose pad octet is not zero is a typed error, because the spec fixes
  it at zero and a non-zero value means the path is already misaligned. Port
  segments pad relative to the **segment start**, not to the running offset,
  which only differs inside a packed path but differs silently there.
- **`cip`.** A reply sets bit 7 of the service code; `Reply` stores the service
  **stripped** and re-encodes it set, and `Request.decode` refuses a message
  with the bit set (and `Reply.decode` one without) rather than reading a
  reply's general status as a path size. `additional_status_size` is counted in
  words and is attacker-controlled — a count of 255 claims 510 octets that may
  not exist — so it is bounds-checked against the buffer.

  **`Multiple_Service_Packet`'s offsets are measured from the start of the
  count field.** Getting that wrong shifts every embedded request by two octets
  plus the table's width and decodes as garbage rather than failing, so both
  directions are asserted against captured traffic. `at(i)` additionally
  requires offsets to be non-decreasing and to point past the table, because an
  out-of-order table would otherwise produce overlapping or negative-length
  slices.

  **Service codes are only unique within an object class.** `0x52` is
  `Unconnected_Send` on class 6 and `Read Tag Fragmented` on a symbol object;
  `0x4E` is `Forward_Close` or `Read Modify Write Tag`. `Service` is therefore
  the *common* services only, the Logix and Connection Manager codes live in
  their own namespaces, and `Request.classCode()` (which reads the class
  segment out of the path) is what the dispatcher consults **before** the code.
- **`connmgr`.** The timeout is `2^(tick & 0x0F)` milliseconds × `ticks`, not a
  number of milliseconds — the everyday `5, 157` is 5024 ms. The upper bits of
  the tick octet are a priority field and must not enter the arithmetic.

  **The `Unconnected_Send` pad octet exists only when the embedded message's
  length is odd.** A decoder that always skips it (or never does) mis-locates
  the route path. **`Forward_Open` has no reserved octet after its
  connection-path size, while `Unconnected_Send` and `Forward_Close` both do**
  — this was found against captured traffic and is the difference between a
  connection that opens and one the target answers with a path-segment error.

  The 16-bit and 32-bit network connection parameters have **different bit
  layouts** (9-bit size with the flags above it, versus a full 16-bit size with
  the flags in the top half), not merely different widths;
  `ConnectionParameters` owns both and `toU16` returns null for a size the
  small form cannot express, which is what makes the choice of
  `Large_Forward_Open` mechanical rather than a guess.

  A `Forward_Close` matches on the `{connection serial, originator vendor,
  originator serial}` **triple**, not on a connection id — it does not carry
  one. Two originators that pick the same serial are told apart by their vendor
  id, which is why all three travel together everywhere.
- **`types`.** The type code is a **16-bit** little-endian value even though
  every elementary type fits in one octet. A structure reply sends `0x02A0`
  followed by a two-octet **structure handle** naming the UDT, and only then
  the member octets; a decoder that treats the handle as data is off by two for
  the whole tag. `date_and_time` (0xCF) is deliberately **not** given an
  element size: the published tables disagree about its width and guessing
  wrong silently mis-slices an array, so it is handed back as `.raw`.

  `Read Tag Fragmented`'s offset is in **octets**, not elements, so a caller
  resuming after a partial read advances by the octets it received.
  `Write Tag` orders its fields `{type, count, values}` and
  `Write Tag Fragmented` `{type, count, offset, values}`; swapping them writes
  plausible garbage. `partial_transfer` (0x06) is **not** an error — it is how
  a fragmented read says "there is more" — which is why `GeneralStatus.hasData`
  exists alongside `isSuccess`.
- **`tagpath`.** Logix's own name rules are checked, not assumed: a name starts
  with a letter or underscore, contains only letters, digits and underscores,
  is at most 40 characters, never contains two consecutive underscores and
  never ends in one. A silently-accepted bad name produces a request the
  controller answers with `path_segment_error`, which is a far worse debugging
  experience than a parse error. `Program:MainProgram` is **one** symbol
  segment including the colon, and the colon is only a scope prefix on the
  first component — anywhere else it is an illegal character.
- **`client`.** Everything a reply hands back points into the client's own
  receive buffer and is invalidated by the next call; that borrowed-slice
  contract is what keeps the client allocation-free, and it is stated at the
  top of the file and in the README. The transmit buffer is split so a request
  and the CPF envelope wrapping it never overlap.

  **Routing is an explicit choice, not a default that happens to work.** A
  ControlLogix chassis needs `Unconnected_Send` with a route path; a leaf
  device answers `path_segment_error` to exactly that message. `Routing` is
  therefore a tagged union with no "auto" case. `forwardOpen`/`forwardClose`
  temporarily force `.direct`, because a Connection Manager request is
  addressed to the *local* device and carries its own route — wrapping it again
  is the classic double-route bug.

  `readTagFragmented` loops on `partial_transfer` with two guards: a round
  ceiling, and a hard error if the target reports "more follows" while sending
  zero octets (which would otherwise loop forever).
- **`adapter`.** A pure function from one message to one message over
  caller-owned tag storage — no program execution, no scan cycle, no access
  control. The reply body is built in a scratch area and only then framed,
  rather than written past the header and framed in place: an in-place frame is
  a `@memcpy` of a region onto itself, which Zig's non-overlap contract does
  not permit. Nesting (`Unconnected_Send` inside `Unconnected_Send`,
  `Multiple_Service_Packet` inside itself) is **depth-capped**, because
  unbounded nesting is a stack-exhaustion primitive a hostile peer controls.

Concurrency: `.single_owner` — one `Client`/`Adapter` owns one connection's
buffers, session handle and sequence counters; nothing is shared or global, and
any threading is the caller's.

Error policy: every decode entry point (`encap.decode`, `encap.Framer.next`,
`encap.Identity.decode`, `encap.Service.decode`, `cpf.decode`,
`cpf.decodeEnvelope`, `cpf.ConnectedData.decode`, `epath.Iterator.next`,
`cip.Request.decode`, `cip.Reply.decode`, `cip.MultipleService.at`,
`connmgr.UnconnectedSend.decode`, `connmgr.ForwardOpen.decode`,
`connmgr.ForwardClose.decode`, `types.decodeValue`, `types.TagData.decode`,
`types.WriteTagRequest.decode`, `tagpath.parse`, `Adapter.handle`) returns a
typed error on malformed input. Nothing panics, allocates or loops unboundedly.

## Verification

### What is third-party-validated

The strongest evidence here is not a hand-written vector — it is **real traffic
between implementations that are not this module**, a **third independent
decoder's** reading of the same octets, and **live round trips in both
directions**.

**Oracles used**, all installed in a throwaway virtualenv or already present,
and all driven **as black boxes only** — to generate wire traffic, to act as a
live peer, and to be diffed against. No third-party source was read as a design
reference. Under CONVENTIONS §5 that is a test oracle, not a design reference,
so **no `/NOTICE` entry is required** — the same status as diffing against
`tar` or `nft`.

1. **`cpppo` 5.2.5**, which ships both an EtherNet/IP client and a simulated
   EtherNet/IP **server** (`python -m cpppo.server.enip`). Both were used.
2. **`pycomm3` 1.2.16**, an independently written Logix driver. Used as a
   second client, and as a second client against *our* adapter.
3. **Wireshark 4.6.4's own `enip`/`cip` dissector**, reached through
   `rawshark` (see the caveat below).

Concretely:

1. **61 byte-exact captured goldens** (`goldens.zig`). Both Python clients were
   pointed at the cpppo server through an encapsulation-aware recording TCP
   proxy (and a UDP one for discovery), and every message that crossed the wire
   was logged as hex. Four assertions run over the whole table:
   - every frame decodes at the encapsulation layer and **re-encodes to the
     identical octets**;
   - every data-carrying frame's CPF envelope decodes, passes
     `validateDataOrder` and re-encodes identically;
   - every CIP request and reply inside decodes and re-encodes identically, and
     **every request's EPATH is rebuilt from its decoded segments** through
     `epath.reencode`, so the path encoder is what is being checked and not a
     memcpy; every `Unconnected_Send`, `Forward_Open`, `Large_Forward_Open` and
     `Forward_Close` body is likewise rebuilt from its decoded fields;
   - a coverage assertion fails if the table ever stops containing
     `RegisterSession`, `UnRegisterSession`, `ListIdentity`, `ListServices`,
     `ListInterfaces`, `SendRRData`, `SendUnitData`, a UDP discovery pair, all
     four CPF item types in use, `Unconnected_Send`, `Forward_Open`,
     `Large_Forward_Open`, `Forward_Close`, `Multiple_Service_Packet`,
     `Read Tag`, `Write Tag`, both fragmented services, `Get_Attributes_All`,
     `Get_Attribute_Single`, a CIP-layer error reply, an encapsulation-layer
     error reply, traffic from **both** client stacks, and INT/DINT/REAL/
     SHORT_STRING tag reads.

   Coverage of the capture: `RegisterSession` with a zero and with a non-zero
   sender context; `ListIdentity` over **TCP and over UDP**; `ListServices`;
   `ListInterfaces` answering an empty list; a legacy `0x0001` command;
   `Read Tag`/`Write Tag` both **routed** (wrapped in `Unconnected_Send` with a
   `1/0` backplane route) and **unrouted** (bare CIP in a null-address CPF); a
   three-request `Multiple_Service_Packet` and its three-reply answer;
   `Read Tag Fragmented` and `Write Tag Fragmented`; a SHORT_STRING write and a
   two-element SHORT_STRING read (one of them empty); an array read; a
   `Forward_Open` at 510 octets and a `Large_Forward_Open` at 4000 octets from
   the *other* stack; two `SendUnitData` exchanges with sequence counts 0 and 1
   on the connection those opened; two `Forward_Close` exchanges;
   `Get_Attributes_All` and `Get_Attribute_Single` (attributes 1 and 7) on the
   Identity object, unconnected and connected; a CIP error reply with a
   non-zero general status; and two encapsulation-layer error replies whose
   body is **zero octets**, which is the shape that breaks a decoder insisting
   on a CPF envelope.

2. **Cross-checked against Wireshark's dissector.** `tshark` is **not**
   installed in this environment (the `wireshark` GUI is, and `apt` shows
   `tshark` as available-but-not-installed; installing it needs root, which is
   not available here). `rawshark`, which ships with the same package set and
   uses the same dissection engine, **is** installed and was used instead: the
   61 goldens were written into a pcap and dissected with
   `rawshark -s -d proto:enip`. Wireshark's reading of `enip.command`,
   `enip.cpf.typeid`, `cip.service` (including the services *inside* an
   `Unconnected_Send` and inside a `Multiple_Service_Packet`), `cip.genstat`
   and `cip.symbol` was compared field by field against this module's:
   **61 packets compared, no mismatched fields.** That comparison is a one-off
   external check and is not part of the test suite (the suite must not depend
   on Wireshark being installed).

3. **Live round trip, our client → a real EtherNet/IP target**
   (`root.zig`, gated on `ENIP_TEST_SERVER`). Against a live cpppo target on
   `127.0.0.1:44818`, the run performed: `RegisterSession`; `ListIdentity` and
   `ListServices` off the encapsulation layer; a `Write Tag` of an INT and a
   read-back compared value for value; a four-element array read; a
   `Read Tag Fragmented`; a two-tag `Multiple_Service_Packet`; a read of a tag
   that does not exist, refused by the target; and `UnRegisterSession`.
   Printed output:

   ```
   live ENIP: session=0x88AD7507 vendor=1 product="…" services="Communications"
   interfaces=0 tag_rw=ok array=4 fragmented=20B batched_first=int
   batched_second_ok=true missing_tag=refused
   ```

4. **Live connected messaging, our client → the same target** (gated on
   `ENIP_TEST_CONNECTED`): `Forward_Open`, three `SendUnitData` exchanges with
   incrementing sequence counts, `Forward_Close`. Printed output:

   ```
   live ENIP connected: o_to_t=0x8236528B t_to_o=0x00000000 exchanges=3 closed=ok
   ```

5. **Live round trip, real third-party clients → our adapter** (gated on
   `ENIP_TEST_LISTEN`). **Both** Python stacks were pointed at our `Adapter`:
   - the cpppo client performed `ListIdentity` (its decoder read our identity
     item correctly: vendor, device type, product code, revision, status,
     serial, product name and state all came out right), `ListServices`, two
     four-element array reads and a write with a read-back that showed the new
     value. Our side printed
     `live ENIP adapter: identity=1 reads=3 writes=1 scada[0]=1 connections_seen=0`.
   - pycomm3 performed `ListIdentity`, an unconnected `Get_Attributes_All` on
     the Identity object, and — the interesting one — a **`Large_Forward_Open`,
     a connected `Get_Attribute_Single`, and a `Forward_Close`** against our
     adapter, all of which its own decoder accepted. Our side printed
     `live ENIP adapter: identity=3 reads=1 writes=1 scada[0]=5 connections_seen=2`.

Both live directions passed in Debug, and the whole suite passes in
`--release=fast`; all three live tests print `SKIPPED: …` and pass when no peer
is present.

One divergence worth recording: **the cpppo target refuses a `Read Tag
Fragmented` that is not wrapped in an `Unconnected_Send`**, answering an
encapsulation-layer `0x0008`. This is a limitation of that target, not of this
module — the cpppo *client* driving the same target unrouted with `--simple
--fragment` gets the identical refusal, and our routed request is byte-for-byte
what the cpppo client sends.

### What is self-derived

- **16- and 32-bit logical segments and their pad octet.** No captured frame
  contains one: every path in the capture uses 8-bit class, instance,
  attribute and member segments. The 16/32-bit forms follow the documented
  layout and are round-trip and hostile-input tested, not captured. The
  `tagpath` tests that produce them (`Big[300]`, `Big[70000]`) are therefore
  self-derived too.
- **The packed (unpadded) EPATH form.** Modelled from the specification and
  round-trip tested; nothing in the capture emits one.
- **The `Unconnected_Send` pad octet for an odd embedded message.** Every
  embedded message in the capture happened to be even-length, so the pad's
  presence is unit-tested against the documented rule rather than captured.
- **Port segments beyond `01 00`.** The extended-link-address form
  (`0x10 | port`, size, address) and the extended-port escape (`0x0F`, 16-bit
  port) are decoded and re-encoded from the documented layout; only the plain
  one-octet backplane form appears in the capture.
- **Network segments and the electronic key.** Decoded and re-encoded from the
  documented layouts; neither oracle emitted one.
- **Structure (UDT) reads.** The `0x02A0` + handle shape is implemented and
  tested from the specification. The simulator used here serves no UDTs, so no
  captured structure read exists. This is the largest self-derived area and is
  called out again under "Deferred".
- **Sequenced Address items and the sockaddr-info items.** Codecs only — see
  "Deferred". No captured frame contains either, because implicit I/O was never
  exercised.
- **CIP data types beyond INT, DINT, REAL and SHORT_STRING.** The remaining
  elementary types are encode/decode round-trip tested against their documented
  codes and widths, not against third-party bytes.
- **`Get_Attribute_List` / `Set_Attribute_List`.** Encoders and a reply
  iterator built from the specification; neither oracle emitted one.
- **The identity in the goldens is anonymised.** Two fields are
  length-preserving substitutions applied identically everywhere they appear
  (the `ListIdentity` replies, `Get_Attributes_All`, `Get_Attribute_Single`
  attribute 7): the simulator's reported product name → the same-length
  `"SIMULATED-CIP-DEVICE"`, and its serial number → `0x00C0FFEE`. Both sit
  inside length-prefixed regions, so no length, offset or checksum changes and
  every frame still decodes and re-encodes byte-identically. A test asserts the
  substitution, so a future capture pasted in unanonymised fails.
- **The oracle target is a *simulator*, not real hardware.** No ControlLogix,
  CompactLogix, MicroLogix, PowerFlex or third-party adapter was available.
  The cpppo server implements the same wire protocol, but quirks specific to
  real firmware (Logix connection-resource limits, the real `0x6B` symbol-object
  tag list, optimised/atomic tag layout, chassis routing through a real 1756-ENBT)
  are by definition not covered — and neither is anything about how a real
  controller behaves when a tag write lands mid-scan.

### Fuzz + hostile input

`std.testing.fuzz` sweeps across every decoder and the tag-path parser, all
asserting "typed error or valid result, never a panic and never a hang":

- `encap.decode` over arbitrary bytes — anything that decodes must re-encode to
  the identical octets and its `total_len` must equal the input length.
- `encap.Framer` fed arbitrary stream bytes in chunks, with a guard counter
  that fails the test if `next` ever returns a message without consuming input.
- `encap.Identity`, `encap.Service` and `encap.SocketAddress` decoders, each
  with a re-encode assertion.
- `cpf.decode` and `cpf.decodeEnvelope` over arbitrary bytes, with a re-encode
  assertion and every typed view (`connectionId`, `SequencedAddress`,
  `ConnectedData`, `socketAddress`) walked over every decoded item.
- `epath.reencode` over arbitrary bytes, plus `findLogical`, `findSymbol`,
  `countSegments` and a **packed** iteration with a step guard.
- `cip.Request`/`cip.Reply` over arbitrary bytes with re-encode assertions.
- `cip.MultipleService` walking, with every slice handed out asserted to lie
  inside the payload.
- `cip.AttributeListIterator` over arbitrary bytes and an arbitrary value
  width, with an iteration guard.
- `connmgr`'s four decoders with re-encode assertions.
- `types.decodeValue` over an arbitrary type code, and `TagData`,
  `WriteTagRequest`, `WriteTagFragmentedRequest` with re-encode assertions plus
  32 element accesses each.
- `tagpath.parse` over arbitrary bytes, with anything that parses required to
  encode to a legal even-length EPATH that re-encodes exactly.
- `Adapter.handle` over arbitrary messages, half of them with a session already
  open, with **anything the adapter emits required to be a legal encapsulation
  message**.
- `Client.readTag` against an arbitrary reply.

Explicit hostile-input tests (not fuzz) cover every case named in the task and
more: an encapsulation length disagreeing with the payload **in both
directions**, a truncated header, non-zero options, a message larger than the
framer's storage; a **CPF item count that overruns** its storage, an **item
length pointing past the buffer**, trailing octets after the last item, a data
item first, a connected address paired with unconnected data and the reverse, a
connected address of the wrong width, a connected data item too short for its
own sequence count, a single-item data CPF; an **EPATH segment whose size runs
past the path** (symbol, 16-bit logical, simple data, extended port), a
**symbolic segment with a zero length**, an **odd symbolic segment with its pad
missing** (which runs into the next segment and is shown doing so), a padded
segment with a dirty pad octet, reserved logical types and formats, and
unmodelled segment types; a **request path size that overruns**, a reply with
the request bit, a request with the reply bit, a dirty reserved octet, an
**additional-status count that overruns** (both by 255 words and by one octet);
a **Multiple Service Packet offset table pointing outside the payload**, one
pointing into the table itself, a table whose own width overruns, and
descending offsets; an `Unconnected_Send` **embedded size that overruns**, a
route-path size that overruns, a dirty reserved octet, a `Forward_Open`
connection-path size that overruns and a truncated `Forward_Open`; a
**SHORT_STRING/STRING length prefix that runs past the data**, a **type code
that contradicts the data length**, a structure reply missing its handle, and
an out-of-range element index on both fixed- and variable-width arrays; roughly
twenty-five malformed tag paths; and five hostile encapsulation messages driven
straight through `Adapter.handle`.

## Threat model

EtherNet/IP is an **unauthenticated, unencrypted** protocol by design: anyone
with a path to TCP 44818 can enumerate a device, read and write every tag it
exposes, and reboot it. This module's job is therefore robustness and
containment, not confidentiality or integrity against an active attacker:

- Hostile or corrupt bytes from a misbehaving controller, a hostile client or a
  MITM resolve to typed errors at every decode entry point.
- No allocation anywhere, and every buffer is caller-supplied and bounded, so a
  hostile peer cannot drive memory growth. Nesting inside `Unconnected_Send`
  and `Multiple_Service_Packet` is depth-capped so it cannot drive *stack*
  growth either.
- **`Reset` (service 0x05) is implemented and is dangerous.** On the Identity
  object it reboots the device; there is no authentication step in front of it
  anywhere in the protocol. It is exposed because a diagnostic tool and a fleet
  simulator both need it and pretending it does not exist does not make a plant
  safer, but: nothing in this module calls it implicitly, it is spelled out in
  full at its call site, and the `Adapter` **refuses it unless `allow_reset` is
  explicitly set**.
- **Writing a tag on a running machine changes what that machine is doing.**
  There is no "safe" write in this protocol and no confirmation step; the
  module offers no guardrail beyond making every write an explicit call.
- **`ListIdentity` broadcast is a network-wide enumeration primitive.** It is
  exactly what an attacker's first packet on an OT segment looks like. Do not
  run a discovery sweep across a segment you do not own.
- **CIP Security (Volume 8) is not implemented.** Deployments must put
  transport security underneath — a VPN, or a CIP-Security-capable stack —
  and callers should hand the `Transport` seam an already-secured stream,
  exactly as the repo's BYO-TLS rule (CONVENTIONS §2) prescribes.
- The adapter is a **simulator, not a controller**: it executes no program,
  enforces no access level and models no safety function. Do not put one on a
  network where something might mistake it for real equipment.

## Deferred

Honest list of what a full EtherNet/IP implementation has and this one does
not:

- **Implicit (Class 0/1 I/O) messaging over UDP 2222 is codec-only.** The
  Sequenced Address item (`0x8002`) and the Sockaddr Info items (`0x8000` /
  `0x8001`) encode and decode, and `Forward_Open` carries the parameters an I/O
  connection needs, but there is **no I/O connection engine**: no cyclic
  producer, no RPI timer, no connection watchdog, no sequence-number gap
  detection, no multicast group management, no Run/Idle header handling on the
  I/O data. Everything driven end to end in this module is **explicit
  (Class 3 / UCMM) messaging**. Building the implicit side means owning a
  real-time cyclic scheduler, which is a project of its own and is the single
  largest thing missing here.
- **CIP Safety (Volume 5).** Not implemented at all, and deliberately not: a
  safety protocol implemented casually is worse than none.
- **CIP Sync / time synchronisation (Volume 2 ch. 7, IEEE 1588).** Not
  implemented.
- **CIP Security (Volume 8)** — EtherNet/IP over TLS/DTLS, the Security
  profiles and the certificate management objects. Not implemented; see
  "Threat model".
- **DeviceNet and ControlNet ports.** Only the EtherNet/IP adaptation is built.
  Port segments can *name* another port so a route through a gateway can be
  expressed, but nothing here speaks those link layers.
- **The Logix symbol and template objects (`0x6B` / `0x6C`).** Uploading a
  controller's tag list and decoding UDT definitions — which is how a real
  driver learns what tags exist and how a structure is laid out — is not
  implemented. `Get Instance Attribute List` (0x55) is named and nothing more.
  Consequently a structure read returns its handle and raw member octets rather
  than named members.
- **Object-model coverage beyond what is built.** Only the Identity object
  (class 1) is served by the `Adapter`. The Message Router, Assembly,
  Connection, TCP/IP Interface (`0xF5`), Ethernet Link (`0xF6`), Port (`0xF4`)
  and Connection Configuration objects are named in `ClassCode` and not
  implemented on the target side; a *client* can of course address any of them
  with the generic attribute services.
- **Connection watchdogs and timeout supervision.** The
  `connection_timeout_multiplier` is carried on the wire and honoured by
  neither side here; there is no timer anywhere in this module and a connection
  is closed only when a `Forward_Close` says so or the transport dies.
- **Multiple concurrent outstanding requests.** The client performs one
  request/reply exchange per call, which is what every explicit-messaging
  driver does in practice.
- **Reconnection, retry and keepalive.** A transport failure is surfaced; a
  production deployment wires reconnection into its own supervisor.
- **PCCC encapsulation (`Execute PCCC`, 0x4B)** for legacy SLC/PLC-5 targets.
  Named, not implemented.
- **`tshark` cross-check** — `tshark` is not installed here and cannot be
  installed without root; the equivalent check was run with `rawshark` from the
  same Wireshark version. See "What is third-party-validated".

## Status

`gap · any (pure codecs + client logic + adapter; only the optional
TcpTransport/UdpDiscovery touch std.Io.net) · both (client + adapter) ·
single_owner` + deps: `netaddr` — canonical source is `pub const meta` in
src/root.zig.

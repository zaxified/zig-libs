# bacnet — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

Four allocation-free wire layers mirroring the standard's own decomposition, plus a datagram
seam and the two roles on top of it — and, since the module now covers **two** data links, a
second link layer (Annex AB, BACnet/SC) with its own node and hub. Every wire struct uses explicit shifts and
`std.mem.readInt`/`writeInt` rather than a `packed struct`, so the octet layout never depends on
Zig's bitfield-packing rules.

- **`tag` (clause 20.2).** The file that earns its keep. A tag header is four fields in one octet
  (number, class, LVT), and each field has an escape:
  - the tag number nibble `0b1111` means "the real number is in the next octet" (numbers 15..254);
  - the LVT means length 0..4 directly, `5` = extended, `6`/`7` = opening/closing bracket;
  - extended length is one octet for 0..253, `254` + `u16` for 254..65535, `255` + `u32` above.
    Note the asymmetry: 253 fits in one octet but 254 costs three. Every one of those boundaries
    is a test.
  - **An application Boolean puts its value in LVT and has no data octets**; a *context* tag
    numbered 1 is an ordinary context tag with a length. Conflating the two is a classic bug.
  - **LVT 6/7 imply the context bit**, because the class bit lives in the same octet. So an
    application tag reading LVT 6 or 7 is genuinely malformed, and `decodeHeader` says so rather
    than inventing a bracket.

  `encodeHeader` always emits the **canonical** form (nibble when the number fits, shortest length
  escape). A peer's non-canonical spelling still decodes; it is simply never re-emitted, and the
  round-trip fuzzer skips exactly that case rather than pretending the two are equal.

  Decoded strings and octet strings are **slices of the caller's input**. Nothing in this module
  allocates, anywhere, including the client and the device.

- **A property value is never interpreted.** `ReadProperty-ACK`'s `propertyValue`,
  `WriteProperty`'s value and a COV notification's values are `ABSTRACT-SYNTAX.&Type` in the
  standard: the datatype comes from the *property definition*, not the wire. They are handed back
  as the raw tagged octets between `[3]`/`]3` (or `[4]`/`]4`, or `[2]`/`]2`), with `tag.Reader`
  available to walk them and `ReadPropertyAck.scalar()` for the common single-datum case —
  which returns `error.UnexpectedTag` when the block holds a list, instead of quietly returning
  its first element.

- **`npdu` (clause 6).** The single most bug-prone layout in BACnet, because the control octet
  decides how long the header is. Three specific traps, each with its own test:
  - the **hop count belongs to the destination bit** but is written *after* the source fields;
  - **`DLEN == 0` is legal** and means "broadcast on DNET" — not a truncation;
  - **`SLEN == 0` is not legal**: a source with no address cannot be replied to.

  Reserved control bits 6 and 4 are *checked*, not ignored: a peer that sets one is either broken
  or probing, and refusing beats guessing which optional fields it thinks it sent. Network lists
  (`I-Am-Router-To-Network`) are big-endian `u16`s, which is nobody's host layout, so the decoded
  union carries an **iterator over the borrowed body** rather than a slice that would need
  byte-swapping into an allocation.

- **`apdu` (clause 20.1) — segmentation is the point.** With the SEG bit set, a
  `Confirmed-Request` or `ComplexACK` carries two extra octets (sequence number, window size)
  *before* the service choice. A decoder that ignores SEG reads the sequence number as the service
  choice and the window size as the first tag, and produces a plausible-looking, completely wrong
  decode. So:
  - `decode` looks at SEG first and returns a typed `SegmentInfo`;
  - `Apdu.serviceData()` returns `error.Segmented` for a segmented PDU, which makes forgetting the
    check impossible for a caller that uses the accessor;
  - `MOR` without `SEG` is refused — there is no segment for "more" to follow;
  - `Client` and `Device` both answer an offered segmented message with
    `Abort(segmentation_not_supported)`, which is what clause 5.4 prescribes for a peer that will
    not reassemble, and report it as a typed event rather than dropping it. Answering *nothing*
    would leave the sender retransmitting the whole transfer.

  `MaxApdu` reserved codes (6..15) return `error.InvalidValue` from `octets()`. Guessing a buffer
  size from a reserved code is how a peer gets to choose your allocation.

- **A wire integer that does not fit its field is refused, never narrowed.** BACnet spells an
  unsigned in 1..8 octets, so a peer chooses the width of every integer it sends, and the fields
  they land in are `u32`, `u8` and `i32`. Every such conversion in `service.zig` goes through
  `narrow`, which answers `error.InvalidParameter`. A bare `@intCast` there is wrong in both
  build modes and differently in each: a *panic* under ReleaseSafe, so one 14-octet datagram from
  unauthenticated UDP 47808 stops the device; a silent *wrap* under ReleaseFast, where an array
  index of 2^32 becomes index 0 — which in BACnet is not the first element but the array's
  **length**, so the device answers a question it was not asked and says nothing about it.

- **A constructed block ends at its own closing bracket.** `Reader.openedBlock(n)` requires the
  bracket that closes the block to carry number `n`, and takes the end of the body from where that
  bracket actually starts. The number and the *width* are separate traps: `[3 … ]99` closes two
  octets wide where one was expected and leaks a header octet into the value, `[99 … ]3` closes
  one octet wide where two were expected and underflows the body length.

- **Non-exhaustive enums everywhere.** BACnet reserves whole ranges for vendors — object types
  ≥ 128, property identifiers ≥ 512, error codes ≥ 256, network message types ≥ 0x80. A decoder
  that refuses an unnamed value is wrong; every enum here is `_`-terminated and an unknown value
  round-trips with its number intact. `isProprietary()` distinguishes "vendor extension" from
  "future standard value", which are different things and are treated differently.

- **`client` / `device`: no clock, no thread, no socket.** The caller passes `now_ms` into every
  entry point and performs the I/O through a `Transport`. That is what makes the APDU timeout
  (3 s default) and the retry ladder (3 retries default) testable with a fake clock instead of a
  twelve-second unit test, and it is why the COV subscription lifetime and expiry are exercised
  offline. Both roles keep **fixed-size** tables (transactions, subscriptions) sized at compile
  time, so capacity exhaustion is a typed error (`TooManyTransactions`, an `Error` PDU with
  `resources`/`no_space_to_add_list_element`) rather than an allocation failure.

  **Invoke ids are recycled but never reused while live.** `nextInvokeId` skips ids still
  outstanding; BACnet gives a client no other correlator between request and response, so reusing
  a live id makes responses ambiguous. A retry is a **resend of the stored datagram**, not a
  re-encode, so a retransmission is guaranteed byte-identical to the original.

  **A transaction is keyed on (invoke id, peer address), never on the invoke id alone.** That is
  what clause 5.4's TSM entry is indexed by, and what `bacnet-stack`'s `tsm.c` compares before it
  touches an entry. It has to be: base BACnet/IP is unauthenticated, and the invoke id is an
  8-bit sequentially-allocated number, so a response matched on the id alone is a response any
  host that can reach the socket can forge — cancelling a transaction it knows nothing about, or
  having its own ComplexACK delivered to the application as the answer the client was waiting
  for. A SimpleACK/ComplexACK/Error/Reject/Abort whose origin does not match the address the
  request went to (and a late one for a transaction that has already completed or timed out) is
  reported as `.unhandled` and retires nothing; the genuine answer, or the timeout, still
  happens. This does mean a device that answers from a *different* source address than the one
  addressed is not understood — that device is non-conforming, and the alternative is accepting
  anybody's answer.

  **A unicast question gets a unicast answer.** A device that receives a Who-Is or Who-Has as an
  `Original-Unicast-NPDU` answers with a unicast I-Am/I-Have; a broadcast question gets a
  broadcast answer with the global-broadcast destination and hop count 255. This was found by
  live interop: a broadcast-only reply never reaches a requester the device cannot broadcast onto
  (behind a BBMD, on loopback, or across a router), and the third-party peer this was tested
  against behaves the same way.

  **A `Forwarded-NPDU` is attributed to the original sender**, not to the BBMD that relayed it.
  Replying to the relay sends the answer to the wrong device.

- **`sc` (Annex AB) — the BVLC without a length field.** Annex J can check its `length` against
  the UDP datagram it arrived in. A BACnet/SC message is delimited by a **WebSocket frame**, so
  there is nothing to cross-check and the only way to find the payload is to walk the header. That
  header is variable in four independent ways (originating VMAC, destination VMAC, destination
  options, data options), and the option lists are **self-terminating**: every option marker has a
  *more-options* bit, so a list that never says "no more" simply runs off the end of the frame.
  `scanOptions` is bounded by the slice it was given and every iteration consumes at least one
  octet, so a hostile list cannot stall; a fuzz test asserts exactly that.

  Three details that are easy to get wrong and each have a test:
  - the **must-understand** bit is what makes forward compatibility work, so an option we do not
    know *and* must understand is a `BVLC-Result` NAK carrying `header_not_understood` and the
    offending marker — never a skip. Both roles enforce it before looking at the function.
  - an option with the *header-data* flag and a **zero-length** data block (`61 0000`) is a
    different thing from an option with no data flag at all (`41`), and they decode differently.
  - a `BVLC-Result` ACK is exactly two octets; trailing octets mean the peer thinks it sent an
    error block, which is a disagreement worth reporting rather than ignoring. A result code that
    is neither ACK nor NAK has no third meaning to guess at.

  **Byte order is big-endian**, as everywhere else in BACnet. This is stated explicitly because
  two third-party implementations disagree about it — see "The byte-order finding" below.

- **`sc_node` / `sc_hub`: the same discipline as `client`/`device`.** No clock, no thread, no
  socket; the caller supplies `now_ms`, owns the WebSocket, and drains a compile-time-sized outbox
  (a caller that stops draining gets `error.OutboxFull`, never an allocation). That is what makes
  a 300-second heartbeat timeout and a 300-second reconnect ceiling testable in microseconds, and
  a 10 000-iteration reconnect storm a unit test.

  - **Reconnect backoff doubles from `SC_Minimum_Reconnect_Time` (2 s) to
    `SC_Maximum_Reconnect_Time` (300 s) and is jittered downward** by up to 25% from the caller's
    `std.Random`. The jitter is the point: a hub reboot must not be answered by every node in a
    building at the same instant.
  - **Hub failover alternates.** After each failed attempt the node tries the *other* configured
    URI rather than hammering the primary; with no failover configured it stays put.
  - **A VMAC collision is a defined outcome, not an error.** The hub answers a Connect-Request
    whose VMAC belongs to a different UUID with `node_duplicate_vmac`; the node draws a new VMAC
    and retries at the floor delay rather than at the doubled backoff, because the collision is
    its own to fix. That is the only reason a node holds a `std.Random`.
  - **The negotiated maxima are enforced on send.** A Connect-Accept may propose *smaller* limits
    than we asked for; from then on an oversized NPDU is `error.MessageTooLong` at the point of
    queuing, not a frame the peer silently drops.
  - **The hub attributes what a node omits.** A node talking to its hub may leave the originating
    VMAC out — the hub knows who it is talking to — and the hub fills it in when forwarding,
    because the receiving node has no other way to know. A node that fills in *somebody else's*
    VMAC is spoofing and is refused. Connection-control messages (Connect, Heartbeat, Disconnect)
    carry no VMACs at all: they travel between one node and its hub and go nowhere else.
  - **Anything before Connect-Accept is refused.** A data message — including a heartbeat —
    arriving while the connection is not established is `error.NotConnected` on the node side and a
    `BVLC-Result` NAK on the hub side, so a stranger cannot drive state through a socket it has
    not been admitted on.

- **`sc_ws`: TLS is a seam, not a pretence.** This collection does not implement TLS. The caller
  terminates it and passes a `TlsAssertion` saying so; it is recorded, reported, and **never
  verified**, because a module that cannot see the certificate cannot verify anything. What it
  *is* used for: a node that cannot assert mutual authentication is refused the `secure_path`
  header option, so it cannot claim a protected path it does not have. Annex AB's actual
  requirements — TLS 1.3, **mutual** authentication (a one-way `wss://` is not BACnet/SC), a
  per-device operational certificate with its issuer certificates and CSR in the Network Port
  object, and real expiry/revocation handling — are documented in `sc_ws.zig` and left to the
  caller, with the matching `types.ErrorCode` values (`tls_client_certificate_expired`,
  `..._revoked`, `tls_server_authentication_failed`, …) available to report them.

  The framing is the sibling `websocket` module's, deliberately: a second RFC 6455 implementation
  living inside a BACnet module is the kind of duplication that goes stale. `sc_ws` adds exactly
  two rules on top — the registered subprotocol must be negotiated (RFC 6455 lets a server answer
  with no subprotocol at all, which an ordinary client shrugs at and a BACnet/SC node must treat
  as a failed connection), and a text frame is a protocol error rather than something handed to
  the BVLC decoder.

Concurrency: `.single_owner` — one `Client`/`Device`/`ScNode`/`ScHub` owns its transaction table,
subscription table, connection table and buffers; nothing is shared or global, and the clock and any threading are the caller's.

Error policy: every decode entry point (`bvll.decode`, `npdu.decode`, `apdu.decode`,
`tag.decodeHeader`, `tag.Reader.*`, every `service.*.decode`, every iterator's `next`,
`Client.poll`, `Device.poll`, `sc.decode`, `sc.scanOptions`, `sc.OptionIter.next`,
`ScNode.onMessage`/`poll`, `ScHub.onMessage`/`poll`) returns a typed error on malformed input. Nothing panics, allocates
or loops unboundedly — `Reader.skip` and `Reader.openedBlock` are bounded by the input buffer, and
a fuzz test asserts `skip` always makes forward progress so a hostile buffer cannot stall it.
`Client.poll` and `Device.poll` swallow *decode* errors into `.none` (a malformed datagram from a
stranger must not kill the loop) while still propagating transport failures.

## Verification

### BACnet/IP: what is third-party-validated

**Oracle used:** Python **bacpypes3 0.0.106** (Joel Bender; MIT, per its PKG-INFO
`License-Expression`) — the reference open-source BACnet stack, able to run both a client and a
virtual device unprivileged on a high port. It was installed in a throwaway virtualenv and used
in three ways: to **generate wire octets**, to **act as a live device**, and to **act as a live
client** against ours.

**One honest caveat on provenance.** While probing bacpypes3's API to find the right call
signature for tag encoding, its `primitivedata.Tag.encode` function was read. That is *source
consulted as a design reference* under CONVENTIONS §5, not black-box use, even though the
algorithm it contains is clause 20.2.1 restated. It needs a `/NOTICE` entry — see "What /NOTICE
needs" below. Everything else about bacpypes3 was black-box: its objects were constructed, its
encoders run, its output printed, and its processes driven over UDP. No other function of its
source was read, and no design decision here was taken from it.

1. **42 byte-exact datagram goldens** (`goldens.zig`, table `wire`). Each is a complete BACnet/IP
   datagram — BVLC + NPDU + APDU + service body — emitted by bacpypes3. Three assertions run over
   the whole table:
   - every datagram decodes at all four layers, and its service body decodes too;
   - every datagram **re-encodes to the identical octets**, rebuilt from the *decoded fields*
     through this module's own APDU/NPDU/BVLC writers — so it is the encoder being checked, not a
     memcpy;
   - a representative subset is asserted field by field, and a separate test rebuilds eleven
     **service bodies from scratch** through `service.*.encode` and the RPM builders and compares
     them to bacpypes3's, so the service encoders are checked rather than carried along as opaque
     bytes.

   Coverage: seven of the eight PDU types (Confirmed-Request, Unconfirmed-Request, SimpleACK,
   ComplexACK, Error, Reject, Abort); services `Who-Is` (four forms including the 22-bit maximum
   instance), `I-Am` (two), `Who-Has` (by name and by id), `I-Have`, `ReadProperty` (three request
   forms including a proprietary property identifier ≥ 512, and five ACK forms covering Real,
   CharacterString, Enumerated, BitString and the array-length read at index 0), `WriteProperty`
   (five forms including the priority array and the NULL relinquish), `ReadPropertyMultiple`
   (three request forms including the `ALL`/`REQUIRED`/`OPTIONAL` wildcards and an array index;
   two ACK forms including a per-property access error), `SubscribeCOV` (subscription,
   cancellation, unconfirmed-indefinite), both COV notification forms, and `ReadRange` (with and
   without a range). A test asserts the table really does contain every one of those PDU types and
   services, so it cannot silently rot.

2. **47 primitive-tag goldens** (`goldens.zig`, table `primitives`), also from bacpypes3, kept
   separate because clause 20.2 is where implementations disagree and a failure there should
   localise instantly. Every one decodes, its header re-encodes canonically, and every
   application-tagged one round-trips through `Value` byte-identically. Covers Null, both
   Booleans, Unsigned at 0/255/256/65535/65536/2³²−1, Signed at every sign-extension boundary
   (−1, −128, −129, 127, 128, −32768, −32769, ±2³¹), Real, Double, OctetString at lengths
   0/1/4/5/6, CharacterString (UTF-8, empty, and an ISO-8859-1 encoding octet), BitString (empty,
   partial, full octet), Enumerated, Date, Time, ObjectIdentifier at both the maximum instance and
   a normal one, context tags 0/5/15/254, opening/closing brackets in both the nibble and extended
   forms, and a zero-length context tag.

3. **The extended-length escape boundaries in `tag.zig`** — the prefixes `65 fd` (253),
   `65 fe 00fe` (254), `65 fe 00ff`, `65 fe 012c` (300), `65 fe ffff` (65535) and
   `65 ff 00010000` (65536) — were likewise produced by bacpypes3 and are asserted as prefixes of
   this module's own output.

4. **Live round trip, our client → a third-party device** (`interop.zig`, gated on
   `BACNET_TEST_DEVICE`). Against a live bacpypes3 `NormalApplication` on `127.0.0.1:47809`
   (Device 599, `analog-input,5` "ZONE-TEMP", writable `analog-value,1` "SETPOINT"), the run
   observed:
   - `Who-Is` (unicast) → `I-Am` reporting device 599, max-APDU 1024, `no-segmentation`,
     vendor 999;
   - `ReadProperty` of `present-value` (Real 72.5), `object-name` (CharacterString, UTF-8 encoding
     octet, "ZONE-TEMP") and `status-flags` (BitString, 4 bits, 4 unused);
   - `ReadProperty` of an absent property and an absent object → `Error` PDUs with
     `property`/`unknown-property` and `object`/`unknown-object`;
   - `WriteProperty` of a Real to the setpoint → `SimpleACK`, then a read-back confirming the new
     value, then a restore of the original;
   - `ReadPropertyMultiple` over two objects with four properties, one deliberately absent →
     one ACK carrying three values and a **per-property access error**;
   - `ReadPropertyMultiple` of five Device-object properties;
   - `SubscribeCOV` → `SimpleACK` followed by the **immediate initial notification** clause
     13.14.2 requires, then a cancellation.

   All of the above passed in **Debug and ReleaseFast**.

5. **Live round trip, a third-party client → our device** (`interop.zig`, gated on
   `BACNET_TEST_LISTEN`). Our `Device` was bound to `127.0.0.1:47811` and driven by a bacpypes3
   `NormalApplication` acting as a client. It observed, from the third-party side:
   - `who_is` → `I-Am device,599 1476 no-segmentation 0`;
   - `ReadProperty` of `analog-input,5` `present-value` = `72.5`, `object-name` = `'ZONE-TEMP'`,
     `status-flags` = `<StatusFlags: >`;
   - `ReadProperty` of `device,599` `object-name` = `'ZIG-BACNET-DEVICE'`,
     `vendor-identifier` = `0`;
   - `ReadProperty` of an absent property → `Error(read-property) property: unknown-property`,
     decoded as such by the third-party client.

   Our device reported `served 7 requests`. **This is the interop run that found a real bug**: the
   device originally always broadcast its I-Am, so the loopback-bound third-party client never saw
   it. Answering a unicast question with a unicast answer fixed it, and is now an offline test as
   well.


### BACnet/SC: what is third-party-validated

Annex AB was verified against **three** independent readings of the standard, which turned out to
be necessary.

6. **29 byte-exact BACnet/SC goldens** (`sc_goldens.zig`, table `wire`), emitted by
   **bacpypes3 0.0.106**'s `bacpypes3.sc.bvll` encoders, driven as a black box (construct the
   LPDU, set its header fields, call `encode()`, print the octets). The same three assertions run
   over the whole table as for the Annex J goldens — every frame decodes, every frame re-encodes
   to the identical octets from its *decoded* fields through this module's own writer, and a
   representative subset is asserted field by field. A coverage test asserts the table contains
   **all thirteen** BVLC functions, and a separate test rebuilds four bodies and one header-option
   list **from scratch** and compares them to bacpypes3's, so the encoders are checked rather than
   carried along as opaque bytes.

   Coverage: all thirteen functions; every combination of the two VMAC control bits; connect
   negotiation at 1400/1300 and at the 65535 maximum; all three `HubConnectionStatus` values; an
   Address-Resolution-ACK both empty and with two URIs; a `BVLC-Result` ACK and both NAK spellings
   (with and without a details string); a secure-path option on the destination list and on the
   data list; a proprietary option with vendor data; a two-option list exercising the
   *more-options* chain; and one frame carrying both VMACs and both option lists at once.

7. **A second implementation, compiled and run as an oracle.** `bvlc-sc.c` from the
   **bacnet-stack** project was compiled standalone (it has exactly one include) and driven
   through its published prototypes for the same vectors. Nothing was copied — see the provenance
   note below.

8. **Wireshark 4.6.4's `bscvlc` dissector**, reached through `rawshark -d proto:bscvlc` (`tshark`
   is unavailable here; `rawshark` reads raw frames from a pipe with a four-word pseudo-header and
   dissects them as a named protocol). Our goldens were dissected field by field and agree:
   `bscvlc.function` = `0x06`/`0x0a`, `bscvlc.control` = `0x00`, `bscvlc.msgid` = 65535 on the
   both-VMACs frame (so it parsed the same header layout), `bscvlc.max_bvlc_length` = **1400** and
   `bscvlc.max_npdu_length` = **1300** on the connect golden, `bscvlc.error_class` = **7** and
   `bscvlc.error_code` = **151** on the NAK golden, `bscvlc.header_length` = **5** on the
   proprietary-option golden, and `bscvlc.hub_conn_state` = `0x02` on the failover advertisement.

#### The byte-order finding

bacpypes3 and bacnet-stack agree on **every structural question**: field order, field widths,
which control bit means what, the option marker's bit layout, that the option Header Length is two
octets, that destination options precede data options which precede the payload, and that a
`BVLC-Result` NAK is marker / class / code / details with no terminator on the details string.

They disagree on exactly one thing. **bacnet-stack writes every 16-bit field little-endian**
(message id, option header length, the connect maxima, the error class and code, the proprietary
vendor id); **bacpypes3 writes them big-endian**. For example, a Heartbeat-Request with message id
1 is `0a 00 00 01` from bacpypes3 and `0a 00 01 00` from bacnet-stack.

Wireshark's dissector breaks the tie: it reads all of those fields with `ENC_BIG_ENDIAN`, and it
returned 1400/1300/7/151/5 for our big-endian goldens. Big-endian is also BACnet's convention
everywhere else — Annex J's BVLC length, the NPDU's DNET/SNET, every clause 20.2 multi-octet
value. **This module is big-endian.** The disagreement is recorded as a live test
(`bacnet_stack_divergence` in `sc_goldens.zig`) rather than a comment, so the decision stays
visible and reviewable. One golden, `encapsulated_secure_path_data`
(`01 01 01 01 41 01 00`), is byte-identical from both oracles because every 16-bit field in it is
a palindrome — which isolates the disagreement to byte order and nothing else.

#### A decoder defect found in the oracle

While running the live tests, bacpypes3 0.0.106's `sc.bvll` **decoder** turned out to consume one
octet too many whenever a VMAC is present and no header options are: it reads a header-option
marker the control octet never announced. With no VMAC at all it is correct, and its **encoder**
is correct in every case — which is why the goldens are taken from the encoder only. The visible
symptoms during the live run were an echoed NPDU short by its first octet, and an
`IndexError: bytearray index out of range` on a frame that carries a VMAC and no body. The live
test asserts the truncated-by-one result explicitly and says why, rather than pretending. Our own
decoder and Wireshark both parse those frames correctly.

### BACnet/SC: what ran live, and exactly what the peer was

Annex AB's *codec* has two independent third-party implementations. Its *connection state
machine* effectively has none that was runnable here:

- **bacpypes3 0.0.106** ships `bacpypes3.sc.bvll` (the codec) and `bacpypes3.sc.service`, but the
  service layer hands every BVLC message straight up to the application and never answers a
  Connect-Request. Its `SCNodeSwitch` also does not start under Python 3.14 without two
  compatibility shims (`websockets` ≥ 12 dropped the handler's `path` argument; Python ≥ 3.12
  forbids bare coroutines in `asyncio.wait`), and even with them it reaches "unbound server".
- **bacnet-stack** implements a full BSC node and hub, but its data link needs **libwebsockets**,
  which needs `libssl-dev` and root to install. Neither was available. Its *codec* was still
  usable, which is where oracle 7 above comes from.

So the live peer is a **hybrid, and is labelled as one** in `sc_interop.zig` and here: every
BVLC-SC octet it sends is encoded by bacpypes3's encoders and every octet it receives is decoded
by bacpypes3's decoders — genuinely third party, over a real TCP socket and a real RFC 6455
handshake — but the *hub policy* on top (admit, answer, forward) is harness code. **These runs
validate our wire format, our WebSocket binding and our framing. They are not an independent check
of our state machine, and must not be read as a certified interop result.**

9. **Live round trip, our node → the peer** (`sc_interop.zig`, gated on `BACNET_SC_TEST_HUB`).
   Over a real TCP connection and a real WebSocket handshake with the `hub.bsc.bacnet.org`
   subprotocol negotiated and the `Sec-WebSocket-Accept` value verified, the run observed:
   - our `Connect-Request` decoded by bacpypes3 with the VMAC, the device UUID and both maxima
     (1497/1497) read back correctly;
   - a `Connect-Accept` encoded by bacpypes3, decoded by us: hub VMAC `fe:00:00:00:00:99`,
     negotiated 1497/1497;
   - a `Heartbeat-Request` from our node answered by a bacpypes3-encoded `Heartbeat-ACK` echoing
     message id 2;
   - an `Encapsulated-NPDU` (a Who-Is) sent to the broadcast VMAC and echoed back — short by one
     octet, because of the bacpypes3 decoder defect above, which the test asserts explicitly;
   - a graceful `Disconnect-Request` answered by a `Disconnect-ACK`, ending in `stopped`.

10. **Live round trip, the peer → our hub** (`sc_interop.zig`, gated on `BACNET_SC_TEST_LISTEN`).
    Our `ScHub` listened on loopback, completed the server-side WebSocket handshake and admitted a
    bacpypes3-encoded node: `admitted vmac 0a:0a:0a:0a:0a:01`, a `Heartbeat-Request` answered with
    a `Heartbeat-ACK` the peer decoded and accepted, a broadcast `Encapsulated-NPDU` correctly
    distributed to nobody (it was the only node), and a `Disconnect-Request` answered with a
    `Disconnect-ACK` that the peer decoded — `served 4 frames, admitted 1`, node left with
    `peer_request`.

    Both live tests passed in **Debug and ReleaseFast**.

    The transport was plaintext `ws://` on loopback. That is the one thing about these runs that is
    deliberately **not** conforming BACnet/SC: this collection does not implement TLS,
    `sc_ws.TlsAssertion.none` says so, and the node consequently declines to claim a secure path.

### What is self-derived

Labelled honestly, because it was **not** checked against another implementation:

- **The BBMD and foreign-device BVLC frames** other than `Forwarded-NPDU` and
  `Register-Foreign-Device` (those two *were* generated by bacpypes3). The
  read/write-broadcast-distribution-table, read-foreign-device-table and
  delete-foreign-device-table-entry frames and their BDT/FDT entry layouts are built from Annex J's
  documented field widths and are only checked against themselves by round trip.
- **All the NPDU network-layer messages.** `Who-Is-Router-To-Network`, `I-Am-Router-To-Network`,
  `I-Could-Be-Router-To-Network` and `Reject-Message-To-Network` vectors come from clause 6.4's
  documented layouts. So do the routed-NPDU shapes (DNET/DADR/SNET/SADR/hop-count present in every
  combination) — the third-party peer was on the same subnet, so nothing routed ever crossed the
  wire.
- **Every segmented PDU**: the segmented `Confirmed-Request`, the segmented `ComplexACK` and the
  `SegmentACK` are built from clause 20.1's field layouts. Neither peer segments, by design, so no
  third-party segmented frame was ever seen. The goldens table deliberately contains **no**
  `SegmentACK`, and a test asserts its absence rather than letting a self-derived vector sit in a
  table labelled third-party.
- **`ReadRange`'s `by_time` and `by_sequence` selectors** (the `by_position` and no-range forms
  came from bacpypes3), and the `BACnetDateTime` sequence inside `by_time`.
- **The whole BACnet/SC connection state machine.** The timer values are Annex AB's documented
  defaults (`BACnetSC_Connect_Wait_Timeout` 10 s, `BACnetSC_Disconnect_Wait_Timeout` 10 s,
  `BACnetSC_Heartbeat_Timeout` 300 s, `SC_Minimum_Reconnect_Time` 2 s,
  `SC_Maximum_Reconnect_Time` 300 s) and every transition is exercised offline against our own
  hub, but no third-party peer implementing the state machine was obtainable (see above). The
  heartbeat *interval* — half the timeout — is this module's choice, not a value the standard
  fixes; it is configurable.
- **The hub's admission policy.** Evicting a stale connection when the same device UUID reconnects,
  refusing the hub's own VMAC and the two reserved VMACs, and refusing a node that claims another
  node's source VMAC are all reasonable readings of Annex AB rather than quoted rules, and no
  third-party hub was available to compare against.
- **Address-Resolution-ACK's URI list splitting.** Annex AB gives no length prefix and no escaping,
  so `uriIterator` splits on spaces; the golden with two URIs came from bacpypes3, the splitting
  policy did not.
- **`ReadPropertyMultiple` device-side against a third-party client**: bacpypes3 0.0.106's own
  `read_property_multiple` *client* helper raised `TypeError: objid` from inside its own code
  against **both** our device and its own device, so it could not drive that path. RPM is
  nevertheless validated byte-for-byte in both directions by the goldens, and end-to-end between
  our own client and device.

## Deferred

Everything below is out of scope for this module as it stands, deliberately and with a reason.

- **MS/TP (clause 9)** — the RS-485 master-slave/token-passing data link. Completely different
  framing (preamble, CRC, token rotation) with a real-time token timer; it belongs in its own
  module and needs a serial port to verify.
- **TLS itself, and certificate handling.** BACnet/SC is *implemented*; the TLS underneath it is a
  seam (`sc_ws.TlsAssertion`), not an implementation. Nothing here terminates TLS, validates a
  chain, checks expiry or revocation, reads the Network Port object's
  `Operational_Certificate_File` / `Issuer_Certificate_Files` / `Certificate_Signing_Request_File`,
  or performs enrolment. A deployment that does not supply mutual TLS is not conforming BACnet/SC,
  and this module says so rather than pretending otherwise.
- **BACnet/SC direct connections.** The `dc.bsc.bacnet.org` subprotocol, `Address-Resolution` and
  `Address-Resolution-ACK` are all encoded, decoded and answered, and `sc_ws.Role.direct` builds
  the right handshake — but the *policy* of deciding to open a direct connection to a peer whose
  URIs you just resolved, and of running node-to-node connections in parallel with the hub
  connection, is not implemented. `sc_node` manages exactly one hub connection.
- **The BACnet/SC Network Port object.** The properties Annex AB adds (`SC_Hub_Function_Enable`,
  `SC_Primary_Hub_URI`, `SC_Failover_Hub_URI`, `SC_Minimum_Reconnect_Time`,
  `SC_Maximum_Reconnect_Time`, `SC_Hub_Connector_State`, the connection-status arrays, the
  certificate files) are this module's *configuration*, not a servable object in `device`. A
  device that must expose its own SC configuration over BACnet has to model it.
- **A BACnet/SC ↔ BACnet/IP router.** Both link layers are present and both hand back NPDUs, but
  nothing joins them: forwarding an NPDU between an `ScNode` and a `Client`/`Device` (with the
  clause 6 network-layer rewriting that implies) is the caller's to write.
- **Hub-to-hub / multi-hub topologies**, and the hub's own `Advertisement` beyond answering a
  solicitation.
- **BACnet/IPv6 (Annex U)** — a different virtual link layer with its own address format.
  `BipAddress.fromIp` deliberately returns null for an IPv6 address rather than pretending.
- **Segmentation reassembly** (clause 5.4's segmentation state machine and the SegmentACK window
  protocol). Segmented PDUs are **parsed correctly and refused explicitly** with
  `Abort(segmentation_not_supported)`; what is missing is buffering the segments and driving the
  window. The consequence is a hard ceiling: a `ReadProperty` of a large `object-list`, or an RPM
  whose answer exceeds the peer's max-APDU, fails cleanly with an `Abort` instead of succeeding.
- **Alarms and events** — `AcknowledgeAlarm`, `GetAlarmSummary`, `GetEnrollmentSummary`,
  `GetEventInformation`, both event-notification services, intrinsic reporting and the Event
  Enrollment object. This is a large sub-protocol with its own state machine.
- **Trend-log record transfer.** `ReadRange` is encoded and decoded, but a `BACnetLogRecord` inside
  the ACK is handed back as raw tagged octets rather than modelled.
- **File services** (`AtomicReadFile`/`AtomicWriteFile`) and **object management**
  (`CreateObject`, `DeleteObject`, `AddListElement`, `RemoveListElement`,
  `WritePropertyMultiple`).
- **Device management** — `DeviceCommunicationControl`, `ReinitializeDevice`,
  `TimeSynchronization`/`UTCTimeSynchronization`, `SubscribeCOVProperty` and the "multiple"
  variants.
- **Private transfer, text message and VT services.**
- **BACnet Network Security (clause 24)** — the security network-layer messages (`Challenge-
  Request`, `Security-Payload`, key update/distribution) are recognised by type and passed through
  uninterpreted. Note that base BACnet has **no authentication of any kind**: any host that can
  reach port 47808 can write any writable property. Treat a BACnet segment as a trust boundary and
  put the access control somewhere else.
- **BBMD *behaviour***, as opposed to its frames. Registering as a foreign device (with its
  30-second grace period and re-registration timer), maintaining a broadcast distribution table
  and re-emitting broadcasts as `Forwarded-NPDU` are policy this module encodes for but does not
  perform.
- **The device's priority array.** `WriteProperty`'s priority is decoded, carried and reported,
  but the device stores one value per property rather than sixteen slots plus a relinquish
  default, so it answers a relinquish with `optional_functionality_not_supported` unless the
  stored value is already Null. A device that needs commandable outputs must model the array
  itself.
- **`COV_Increment`.** The device notifies subscribers on every `update`, not only when the change
  exceeds the object's COV increment. A real analog object should filter.
- **Character-string transcoding.** Encodings other than UTF-8 (DBCS, JIS, UCS-2/4, ISO-8859-1)
  are *reported* with their encoding octet and handed over as raw octets; `asUtf8()` returns null
  for them rather than mis-decoding. Transcoding is the caller's problem.
- **Non-canonical tag re-emission.** A peer may spell a tag number below 15 in the extended form;
  this module decodes it but always re-emits the canonical spelling, so such a frame does not
  round-trip byte-identically. This is deliberate.

## What /NOTICE needs

The existing entry is unchanged and still correct:

> **bacpypes3** (Joel Bender, MIT) — Python BACnet stack. Used as a black-box test oracle (wire
> octets, live device peer, live client peer) throughout `modules/bacnet`, which needs no entry;
> **but** its `primitivedata.Tag.encode` function was read while probing its API, which makes it a
> consulted design reference for the clause 20.2 tag encoder in `modules/bacnet/src/tag.zig`.

**The Annex AB work needs no new entry, and here is the honest accounting of what was consulted.**

- **bacpypes3** was used the same way as before: black box. For BACnet/SC its class names,
  constructor signatures and attribute names were discovered with `dir()` and
  `inspect.signature()` — API probing, not source reading — and its encoders and decoders were
  then run. **No bacpypes3 source function was read for the BACnet/SC work.** The one exception
  already covered by the entry above (`primitivedata.Tag.encode`) is unrelated to Annex AB. The
  harness that drives it lives outside the repository.
- **bacnet-stack** (Steve Karg and contributors; GPL-2.0 with a linking exception) was cloned,
  and `src/bacnet/datalink/bsc/bvlc-sc.c` was **compiled and executed** as a black-box oracle.
  What was *read* is its public header `bvlc-sc.h` — function prototypes, struct field names and
  enumerator names — which is API probing of the same kind, plus its `bsc/README.md` and
  `bsc-conf.h` defines for the certificate-file instance numbers cited in `sc_ws.zig`. **No
  implementation function was read, nothing was ported, and none of its code or output is
  vendored: its octets were used only to *disagree* with, and the disagreement is recorded as a
  test.** Because nothing was copied and nothing was read beyond declarations, this is not a
  derivative work and needs no `/NOTICE` entry; if the collection's policy is to name every oracle
  regardless, the entry would be:
  > **bacnet-stack** (Steve Karg et al., GPL-2.0-with-linking-exception) — C BACnet stack. Its
  > `bvlc-sc.c` was compiled and run as a black-box byte-order oracle for `modules/bacnet/src/sc.zig`;
  > only its public header declarations were read. Nothing was ported.
- **Wireshark** was used only as an installed tool (`rawshark -d proto:bscvlc`). Its dissector
  source was consulted **once, remotely and read-only**, to answer the single question of whether
  it dissects the BACnet/SC 16-bit fields as `ENC_BIG_ENDIAN` — a fact about the standard, not a
  design. No Wireshark code was read for structure and none was ported.

Nothing was ported from anything. ASHRAE 135 itself is a published specification and needs no
entry (merger doctrine); its clause citations live in this file and in the module's doc comments.

## What the coordinator should add

- **`/NOTICE`**: nothing is strictly required (see above). If the collection prefers to name every
  black-box oracle, add the two-line `bacnet-stack` entry quoted above.
- **The root `README.md`** module table: the `bacnet` row's one-line summary now covers **two**
  data links — suggested wording: *"BACnet/IP (Annex J) and BACnet/SC (Annex AB): codec, client,
  device, SC node and SC hub"*.
- **`check-catalog`**: `bacnet` is already catalogued; no new module was created. Six new source
  files were added inside it (`sc.zig`, `sc_ws.zig`, `sc_node.zig`, `sc_hub.zig`, `sc_goldens.zig`,
  `sc_interop.zig`) and all six are named in `root.zig`'s dark-tests aggregator.
- **CI**: the two new gated variables (`BACNET_SC_TEST_HUB`, `BACNET_SC_TEST_LISTEN`) are unset in
  CI and skip gracefully, like the existing two.

# bacnet — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

Four allocation-free wire layers mirroring the standard's own decomposition, plus a datagram
seam and the two roles on top of it. Every wire struct uses explicit shifts and
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

  **A unicast question gets a unicast answer.** A device that receives a Who-Is or Who-Has as an
  `Original-Unicast-NPDU` answers with a unicast I-Am/I-Have; a broadcast question gets a
  broadcast answer with the global-broadcast destination and hop count 255. This was found by
  live interop: a broadcast-only reply never reaches a requester the device cannot broadcast onto
  (behind a BBMD, on loopback, or across a router), and the third-party peer this was tested
  against behaves the same way.

  **A `Forwarded-NPDU` is attributed to the original sender**, not to the BBMD that relayed it.
  Replying to the relay sends the answer to the wrong device.

Concurrency: `.single_owner` — one `Client`/`Device` owns its transaction table, subscription
table and buffers; nothing is shared or global, and the clock and any threading are the caller's.

Error policy: every decode entry point (`bvll.decode`, `npdu.decode`, `apdu.decode`,
`tag.decodeHeader`, `tag.Reader.*`, every `service.*.decode`, every iterator's `next`,
`Client.poll`, `Device.poll`) returns a typed error on malformed input. Nothing panics, allocates
or loops unboundedly — `Reader.skip` and `Reader.openedBlock` are bounded by the input buffer, and
a fuzz test asserts `skip` always makes forward progress so a hostile buffer cannot stall it.
`Client.poll` and `Device.poll` swallow *decode* errors into `.none` (a malformed datagram from a
stranger must not kill the loop) while still propagating transport failures.

## Verification

### What is third-party-validated

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

   All seven live client tests passed in **Debug and ReleaseFast**.

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
- **BACnet/SC (Annex AB)** — the WebSocket + TLS secure-connect data link. Would ride on the
  `websocket` sibling module, but needs a hub implementation and certificate handling.
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

One entry, as a **design reference** under CONVENTIONS §5:

> **bacpypes3** (Joel Bender, MIT) — Python BACnet stack. Used as a black-box test oracle (wire
> octets, live device peer, live client peer) throughout `modules/bacnet`, which needs no entry;
> **but** its `primitivedata.Tag.encode` function was read while probing its API, which makes it a
> consulted design reference for the clause 20.2 tag encoder in `modules/bacnet/src/tag.zig`.

Nothing was ported. No other bacpypes3 source was read. ASHRAE 135 itself is a published
specification and needs no entry (merger doctrine); its clause citations live in this file and in
the module's doc comments.

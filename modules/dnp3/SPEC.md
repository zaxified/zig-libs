# dnp3 — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

Six allocation-free layers, all offline-testable, mirroring IEEE 1815-2012's own layering:

- `link` (§9): the fixed 0x0564 frame. `length` (octet 2) = `5 + user_data.len`, excluding every
  CRC octet. The header block (10 octets: start x2 + length + control + dest + src + CRC) is
  followed by user data split into ≤16-octet blocks, each with its own trailing CRC-16. `Control`
  is a plain struct with explicit bit-shift `toByte`/`fromByte` (not a `packed struct`) so the wire
  layout doesn't depend on Zig's bitfield-packing rules.
- `transport` (§8): one octet (FIN/FIR + 6-bit sequence) per link-frame-sized chunk. `Segmenter`
  produces chunks of up to `link.max_user_data_len - 1` bytes; `Reassembler` enforces that every
  non-FIR segment's sequence is the previous + 1 (mod 64), and that a fresh FIR segment always
  restarts reassembly (discarding any in-flight partial fragment), matching §8.2.3.
- `application` (§4/§5): a 2-byte request header (control + function) or 4-byte response header
  (control + function + IIN1 + IIN2). `FunctionCode` is a non-exhaustive `enum(u8)` — unknown wire
  bytes decode, they just don't match a named tag.
- `objects`: object-header framing (group + variation + qualifier byte [prefix nibble + range
  nibble] + a range field whose width/shape depends on the range nibble) plus the core object
  library. The qualifier/range API is deliberately explicit — the caller states the qualifier it
  wants; `encodeObjectHeader` does not auto-pick the smallest encoding. The shared 1-byte `Flags`
  type documents which bits are always the same across groups (ONLINE/RESTART/COMM_LOST/
  REMOTE_FORCED/LOCAL_FORCED) versus group-specific (bit 5, bit 7) rather than pretending
  certainty on nomenclature this implementation isn't set up to test group-by-group.

- `records`: a table-driven codec for the object *records* that follow an object header. A
  group/variation is described by a `Layout` — `{ flags: bool, value: ValueShape, time: TimeShape }`
  — and one `encode`/`decode` pair handles all of them. This is what makes the outstation's ~40
  group/variation pairs tractable: adding a variation is one table row, not a new struct. The
  binary and double-bit families carry their state *inside* the flags octet (bit 7, bits 6-7), and
  `encode` merges the state into the flags for the caller so it cannot be forgotten. Packed
  single-bit (g1v1, g10v1) and packed double-bit (g3v1) shapes are refused by the record codec and
  handled by explicit `setPackedBit`/`setPackedDoubleBit` helpers, because their size depends on the
  range rather than on the variation.
- `outstation`: the responder. `Outstation.handle(request, now_ms, out) -> ?Reply` is a pure
  function from one application fragment to one application fragment over a caller-owned
  `Database` (seven slices of point structs) and a caller-owned `EventBuffer`. `Session` composes
  it with `transport.Reassembler`/`Segmenter` and `link` so a caller can feed whole frames.
  `Session` frames all three outbound directions — `feedFrame` (a reply to a request),
  `nextFrames` (the continuation of a multi-fragment response) and `unsolicitedFrames` (an
  outstation-initiated unsolicited response) — because all three share `Session.tx_seq`, and a
  caller that frames an outstation-initiated fragment itself has to duplicate that sequence
  bookkeeping. `unsolicitedFrames` was added after `fleetsim`'s DNP3 adapter did exactly that
  re-implementation over the public `link`/`transport` API; it is additive, and the fragment-level
  `Outstation.unsolicited` is unchanged for callers that own their own framing.
  Everything time-dependent — the select-before-operate window, the confirm timeout — is driven by
  an injected `now_ms` or by an explicit `confirmTimedOut()` call; the module owns no clock and
  spawns no thread.

Concurrency: `.reentrant` for the codecs — every type (`Segmenter`, `Reassembler`,
`FrameReceiver`, `records`) is caller-owned with no shared/global state; `Outstation`/`Session` are
`.single_owner` (they hold session state: IIN bits, event buffer, select arm, fragmentation
cursor). Error policy: malformed/short/corrupt bytes never panic in `link`/`transport`/
`application`/`objects`/`records` — every decode path returns a typed error — and the outstation
never returns an error for anything a *peer* got wrong: a hostile request becomes a response with
the appropriate IIN bits (`PARAMETER_ERROR`, `OBJECT_UNKNOWN`, `FUNC_NOT_SUPPORTED`) or a command
echo with a non-success `CommandStatus`. The only error `handle` can return is `BufferTooSmall`,
which is a local programming mistake.

## Outstation behaviour worth pinning down

- **Restart IIN.** Set at construction and after every honoured restart. Cleared *only* by an
  explicit WRITE of g80v1 index 7 with the bit clear (§5.1.4.1) — a master that never clears it
  keeps being told, which is the point.
- **Events are retired on CONFIRM, not on send.** A response carrying events sets CON; the events
  stay in the buffer, marked in-flight, until the master's CONFIRM arrives. `confirmTimedOut()`
  un-marks them so the next poll offers the same ones again. Overflow drops the *oldest* and
  latches IIN2.3 until the buffer drains completely.
- **Fragmentation.** Each fragment of a multi-fragment response carries the *next* application
  sequence number (§5.1.6.2) and clears FIR after the first. Reusing the request's sequence for
  every fragment is a classic interop failure and is exactly what opendnp3 caught in this module's
  first draft.
- **Select-before-operate.** The SELECT is stored with its arm time and its object bytes verbatim.
  An OPERATE must carry the SELECT's sequence + 1 and byte-identical objects; otherwise it is
  `NO_SELECT`. Once the arm window closes the select is dropped and the *next* OPERATE is answered
  `TIMEOUT` rather than `NO_SELECT`, so the master can tell the two apart.
- **Link direction.** §9.2.4.1.2's DIR bit is 1 for master-originated frames and 0 for
  outstation-originated ones. `Session` sends 0. Getting this backwards makes a real master drop
  every reply as "master frame received for master".

## CRC verification

DNP3's link-layer CRC-16 is the reveng CRC-catalogue "CRC-16/DNP": width=16, poly=0x3D65,
init=0x0000, refin=true, refout=true, xorout=0xFFFF, check("123456789")=0xEA82. `link.crc16` is a
table-driven implementation (table built from the reflected polynomial 0xA6BC =
`reflect(0x3D65, 16)`, matching the `refin`/`refout` convention).

The CRC was originally cross-checked against a **from-scratch bit-serial reference implementation**
written directly from the (width, poly, init, refin, refout, xorout) parameters — an independent
second implementation of the algorithm (not a port of the Zig table-driven code), which reproduces
the catalogue check value and agrees with the table-driven implementation on every vector in
`link.zig`'s test file (empty input, single bytes 0x00/0xFF, short ASCII strings, a 16-byte
sequential block, a 16-byte repeated block, and two synthetic 8/13-byte link-header-shaped blocks).
That gap is now closed. `src/goldens.zig` replays real link frames from live opendnp3 sessions
(see Verification below); opendnp3 built and validated the CRC on every frame this module sent, and
this module validated the CRC on every frame opendnp3 sent, in both roles. Wireshark's DNP3
dissector also parsed all 43 captured frames without a single CRC or malformed indication.

The remaining full-stack round-trip tests in `link.zig`/`root.zig` are still self-consistency tests
(encode with this module, decode with this module, assert equality) and are documented as such.

## Threat model / out of scope

DNP3 (outside Secure Authentication) is an unauthenticated, unencrypted field protocol by design —
this module's job is robustness, not confidentiality/integrity against an active attacker. Hostile
or corrupt bytes from a misbehaving device or a MITM resolve to typed errors, never panics or
out-of-bounds reads, across every decode entry point (`link.decodeFrame`,
`transport.Reassembler.feed`, `application.decodeRequestHeader`/`decodeResponseHeader`,
`objects.decodeObjectHeader`, every `gNN.VN.decode`).

The outstation widens the attack surface, so its entry points get the same treatment: a request
fragment that is not FIR+FIN, an object header whose range is inverted or empty, a range or count
that runs past the database, a count that overruns the fragment, a start/stop range spanning the
whole 32-bit space, a prefix-less command header naming a point index past the 16-bit index space,
a variation the module does not implement, an unassigned function code, and a zero-length fragment
all resolve to a response with the right IIN bits rather than an error or a crash. Wire-driven
object-instance counts always go through `objects.Range.objectCount()` / `objectSpanBytes()`, whose
arithmetic is widened to `u64`; a raw `stop - start + 1` on a wire value is a defect, and an index
that does not fit the 16-bit point space is refused, never truncated onto a different point.

`Session.feedFrame` filters on the data-link destination address: a frame addressed to another
station is dropped without being decoded further, and the three IEEE 1815 broadcast addresses
(0xFFFD-0xFFFF) are executed but never answered. It does **not** filter on the source address, and
an armed SELECT is not bound to the peer that armed it — on a link where more than one station can
send, authorising the source is still the caller's job (or DNP3-SA's).

Four fuzz harnesses back this: two 20 000-iteration loops over uniformly random bytes (application
fragments, link frames through a `Session`), and two over *structured* draws — function code,
group/variation, qualifier, and range fields drawn from the boundary values of each field's
representable range, which is the only way a fragment ever reaches the command path's range
arithmetic. The structured loops assert they produced those shapes, so a generator that stops
reaching them fails rather than reading green. `std.testing.fuzz` targets over the same generator
(`Outstation.handle`, `Session.feedFrame`) hand the shape space to the real fuzzer.

Out of scope: unsolicited *retry* policy (the fragment builder is here, the timer is the caller's),
file-transfer objects (g70), data-set objects (g85-g88), device attributes (g0), octet strings
(g110/g111), time-and-interval (g50v4), analog deadbands (g34), data-link *confirmed* user data on
the send path (the outstation always sends unconfirmed user data; the FCB/FCV toggle is decoded but
not enforced), Secure Authentication integration into the outstation (`sa.zig` is a standalone
codec), a stateful master session type, and any actual transport (TCP/serial) I/O — this module
hands the caller bytes to send/receive, nothing more.

## g120 Secure Authentication — SAv2 symmetric core

`sa.zig` implements the SAv2 symmetric authentication of IEEE 1815-2012 §7 / IEC 62351-5 over
object group 120:

- **AES Key Wrap (RFC 3394)** — via the shared `modules/aeskw` module (`aeskw.wrap`/`aeskw.unwrap`
  over `std.crypto.core.aes`, AES-128 and AES-256 KEK; std ships no key-wrap). Byte-exact against
  the RFC 3394 §4 published vectors. This used to be a local copy in `sa.zig`; it has been
  collapsed onto the canonical extracted module, which `jwe` and `xmlenc` also use.
- **MAC algorithms** (`mac`) — the SA algorithm registry: HMAC-SHA-1 (truncated to 4/8/10 octets),
  HMAC-SHA-256 (truncated to 8/16 octets), and AES-GMAC (12-octet tag), all via `std.crypto`, with
  constant-time verification (`std.crypto.timing_safe`-style byte compare).
- **g120 codecs** — `Challenge` (v1), `Reply` (v2), `AggressiveModeRequest` (v3),
  `SessionKeyStatusRequest` (v4), `SessionKeyStatus` (v5), `SessionKeyChange` (v6), `SaError` (v7),
  `AggregateMac` (v9), plus the group-120 free-format object header (qualifier `0x5B`).
- **Flow + state** — `computeReplyMac`/`verifyReplyMac` (challenge-response MAC input),
  `wrapSessionKeys`/`unwrapSessionKeys`, and `SeqCounter` / `KeyExpiry` / `lookupUpdateKey` state
  helpers that take the clock/counters as parameters (no wall-clock dependence).

**Corrected from the earlier scaffold** (cross-checked against the Wireshark DNP3 dissector,
`epan/dissectors/packet-dnp.c`): the `HmacAlgorithm` id/truncation table (scaffold listed
nonexistent SHA-3 variants and wrong SHA-1/SHA-256 lengths); the `KeyStatus` ordering (OK=1,
NOT_INIT=2, not the reverse); the `SaError` field order + a missing user-number field; and the
`Challenge` object's missing user-number + reason fields. The variation numbers themselves
(v1/v2/v3/v4/v5/v6/v7/v9) were already correct.

**MAC-input construction (security crux):** the reply MAC is computed over the received challenge
message concatenated with the critical ASDU being authenticated; callers pass the exact wire byte
slices and both sides must agree on their definition. This follows the §7 description and is
validated for full-flow self-consistency (build→verify accept; flip one byte of the MAC or of the
authenticated ASDU → reject). It is **not** validated against a live opendnp3 golden MAC vector
(modern opendnp3 dropped its SA implementation), so wire-level MAC interop remains unproven; the
primitives underneath (AES-KW, HMAC truncation, GMAC) are KAT-exact.

**Out of scope:** the SAv5/SAv6 asymmetric update-key change (g120 v8/v10–v15: RSA/DSA-signed
remote update-key change, user certificates, user-status change), and the DNP3-specific AES-GMAC IV
derivation (the GMAC primitive is provided and KAT-validated; the caller supplies the 12-octet IV).

## Verification

139 offline tests (`zig build test-dnp3`, green in Debug + ReleaseFast; `zig fmt --check` clean).
Breakdown: `link` (12) — CRC catalogue + KAT vectors, control-octet round-trip, frame round-trips
(empty/short/multi-block/exact-16-byte-boundary user data), encode/decode error paths including a
malformed-input sweep; `transport` (9) — transport-octet round-trip, empty-fragment/single-segment/
multi-segment segmentation+reassembly, sequence-mismatch/continuation-before-FIR/FIR-restart/
buffer-too-small/empty-segment error paths; `application` (7) — app-control round-trip, IIN
round-trip, request/response header round-trips, `buildRequest`, short-fragment errors,
non-exhaustive function-code decode; `objects` (20) — qualifier byte round-trip, object-header
round-trips for every implemented range shape (1/2/4-byte start-stop, all-values, count+prefix,
4-byte count), range/qualifier-mismatch and value-out-of-range errors, a short/garbage decode
sweep, flags-byte round-trip, and an encode/decode round-trip for every core object
(g1v1 packed bits, g1v2, g12v1 CROB, g20v1/v2, g30v1/v2, g40v1, g41v1/v2/v3, g50v1) plus a
short-record error sweep; `sa` (20) — AES-KW RFC 3394 §4.1/§4.3/§4.6 vectors + wrong-KEK/corruption
reject + malformed-length errors (integration tests through the shared `modules/aeskw` module, which
carries its own byte-exact KAT suite), HMAC-SHA-256 (RFC 4231) and HMAC-SHA-1 (RFC 2202) truncation KATs,
AES-GMAC (McGrew GCM test case 1) + compute/verify, constant-time verify accept/tamper/wrong-length,
g120 object-header + v1/v3/v4/v5/v6/v7/v9 codec round-trips, short/garbage decode sweep, session-key
wrap/unwrap (128- and 256-bit, wrong-update-key reject), the full challenge-response flow
(build v1 → compute v2 → verify accept; tamper MAC or ASDU → reject), and the `SeqCounter`/
`KeyExpiry`/`lookupUpdateKey` state helpers; `root` (4) — full link→transport→application
stack round-trips (single-frame and forced multi-frame >250-byte fragments) and a
master-builds-READ/outstation-parses + outstation-builds-RESPONSE/master-parses round trip;
`records` (11) — the layout table's wire lengths against the object library, state-in-flags
encoding for binary and double-bit, absolute-time and float variations, narrow-variation range
rejection, packed shapes, a short-record sweep, and the point-kind ↔ group mapping both ways;
`outstation` (51) — IIN (restart set/cleared, need-time, class bits, overflow latch,
func-not-supported, object-unknown), READ (class 0 walking all seven point types in order, every
qualifier shape, variation 0 per-point selection, packed variations, mixed-variation header
splitting, hostile ranges), events (oldest-first with the right group/variation/index prefix,
confirm retires, timeout releases, per-class filtering, direct event-group reads with and without
a count limit, ring overflow semantics), commands (SELECT+OPERATE, timeout, wrong sequence,
different objects, different index, DIRECT_OPERATE and its no-ack form, all four CROB operations,
nonexistent and command-less points, analog output bounds, hook veto), DELAY_MEASURE, restart
(refused and allowed), ENABLE/DISABLE_UNSOLICITED, unsolicited responses, freeze and freeze-clear,
ASSIGN_CLASS, fragmentation (FIR/FIN/SEQ across a series, and a new request abandoning one),
`Session` (link-service replies, a frame addressed to another station dropped, a broadcast executed
but unanswered, a request split across transport segments, out-of-order segments, bad CRC,
`unsolicitedFrames` framing an outstation-initiated response and advancing `tx_seq`), hostile input
(including a full-width command range and a point index past the 16-bit space), and four fuzz
harnesses; `goldens` (5) — the captured-session replays.

**Interop (2026-07-23).** The captures in `src/goldens.zig` were taken against **opendnp3**
(Apache-2.0, `release` branch, built from source in this sandbox) used strictly as a black-box
peer:

1. *`master-demo` → this outstation*, over a real loopback TCP socket with a byte-moving proxy in
   between. Startup tasks, integrity scan (class 3/2/1/0), an ad-hoc `ScanRange(g1v2, 0, 3)`,
   DISABLE_UNSOLICITED, a CROB select+operate that opendnp3 reported as
   `Received command result w/ summary: SUCCESS`, a class-1 exception scan across an injected
   process-image change (which returned a g11v2 binary-output event and a g2v2 binary-input event
   and was CONFIRMed), a COLD_RESTART reported as `Success, Time: 100`, and a second integrity
   scan after the master cleared the restart IIN with a WRITE of g80v1. No protocol warnings.
2. *The same master against a fragmented response*: 300 binary inputs and `max_tx_fragment = 400`,
   so the class-0 scan spans multiple fragments. opendnp3 confirmed each non-final fragment and
   reassembled the series with no "Response with bad sequence" warnings.
3. *This module's master-side codecs → opendnp3's `outstation-demo`*, the reverse direction, which
   cross-checks the pre-existing parsers against a third-party encoder: an unsolicited NULL
   response, five g1v2 binary inputs, ten g20v1 counters and a g52v2 time delay, all decoded.

Replaying sessions 1 and 2 **in order** reproduces every reply byte for byte, 48-bit event
timestamps included, because the tests advance the same injected clock the harness did.

Two real interop bugs were found this way and fixed:

- The outstation set the link-layer **DIR bit** as if it were the master. opendnp3 logged
  `Master frame received for master` / `Frame w/ unknown route, source: 10, dest 1` and dropped
  every reply. §9.2.4.1.2: DIR is 1 for master-originated frames, 0 for outstation-originated ones.
- **Continuation fragments reused the request's application sequence number** instead of
  incrementing it (§5.1.6.2), so opendnp3 logged `Response with bad sequence` and stalled on every
  multi-fragment response.

**Independent dissection.** The captured session was written to a pcap (Ethernet/IPv4/TCP framing
so the dissector sees port 20000) and dissected with Wireshark 4.6.4's DNP3 dissector via
`rawshark` (`tshark` is not installed). All 43 frames dissected cleanly with **zero** malformed or
expert-error indications, and every field matched this module's decoder: DIR/PRM (1/1 on the
master's frames, 0/1 on ours), link addresses (10←1 and 1←10), application function codes (READ 1,
WRITE 2, SELECT 3, OPERATE 4, CONFIRM 0, COLD_RESTART 13, DISABLE_UNSOLICITED 21, RESPONSE 129),
FIR/FIN/CON/SEQ, `dnp3.al.iin.rst` set before the WRITE of g80v1 and clear after, `dnp3.al.iin.cls1d`
set exactly on the responses that carried class-1 events, and the object identifiers in each
class-0 response (0x0102 g1v2, 0x0302 g3v2, 0x0a02 g10v2, 0x1401 g20v1, 0x1501 g21v1, 0x1e01 g30v1,
0x2801 g40v1) plus 0x0b02/0x0202 on the event response and 0x3402 (g52v2) on the restart reply.

## Backlog / deferred

- **Unsolicited retry policy.** `unsolicited()` builds the fragment and `confirmTimedOut()` puts
  the events back; the retry timer, the back-off and the "unsolicited allowed after the first
  integrity poll" convention are the caller's.
- **File transfer (g70), data sets (g85–g88), device attributes (g0), octet strings (g110/g111),
  time-and-interval (g50v4), analog deadbands (g34), time-sync with delay compensation
  (g50v2/g51).**
- **Secure Authentication integration.** `sa.zig` is a complete SAv2 symmetric codec, but nothing
  in `outstation.zig` wraps or unwraps a fragment in g120 objects yet.
- **Data-link confirmed user data on the send path.** The outstation answers RESET_LINK_STATES,
  TEST_LINK_STATES and REQUEST_LINK_STATUS and accepts both confirmed and unconfirmed user data,
  but always *sends* unconfirmed user data; the FCB/FCV toggle is decoded, not enforced.
- **Relative-time event variations (g2v3, g4v3)** are encodable by `records` but the outstation
  never selects them; it always emits absolute time.
- **A stateful master session type** (poll scheduler, task queue, response-timeout state machine) —
  the master role is still the pure codecs.
- **pydnp3** could not be used as a second peer: its sdist needs a CMake build of a vendored
  opendnp3 that fails on Python 3.14 in this environment. opendnp3's own C++ demos were built and
  used instead.

## Status

`gap · any (pure codec + outstation, no I/O) · both (master codecs + a stateful outstation) ·
reentrant codecs, single-owner Outstation/Session` + deps: none (std only) — canonical source is
`pub const meta` in src/root.zig.

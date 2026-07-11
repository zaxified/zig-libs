# dnp3 — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

Four allocation-free layers, all offline-testable, mirroring IEEE 1815-2012's own layering:

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

Concurrency: `.reentrant` — every type (`Segmenter`, `Reassembler`, `FrameReceiver`, etc.) is
caller-owned with no shared/global state. Error policy: malformed/short/corrupt bytes never panic
in `link`/`transport`/`application`/`objects` — every decode path returns a typed error.

## CRC verification

DNP3's link-layer CRC-16 is the reveng CRC-catalogue "CRC-16/DNP": width=16, poly=0x3D65,
init=0x0000, refin=true, refout=true, xorout=0xFFFF, check("123456789")=0xEA82. `link.crc16` is a
table-driven implementation (table built from the reflected polynomial 0xA6BC =
`reflect(0x3D65, 16)`, matching the `refin`/`refout` convention).

No independent DNP3 tooling (`tshark`, `pydnp3`, `opendnp3`) was available in this sandbox
(checked: no `tshark` binary, no `pydnp3`/`dnp3` Python module, and PyPI package installation was
not attempted beyond a reachability check — this was a scope/time call, not a blocked network).
Instead, the CRC was cross-checked against a **from-scratch bit-serial reference implementation**
written directly from the (width, poly, init, refin, refout, xorout) parameters — an independent
second implementation of the algorithm (not a port of the Zig table-driven code), which reproduces
the catalogue check value and agrees with the table-driven implementation on every vector in
`link.zig`'s test file (empty input, single bytes 0x00/0xFF, short ASCII strings, a 16-byte
sequential block, a 16-byte repeated block, and two synthetic 8/13-byte link-header-shaped blocks).
This is a legitimate independent cross-check of the *arithmetic*, but it is not a byte-for-byte
comparison against a real DNP3 stack's captured wire traffic — that remains open (see Backlog).

Full-frame and full-stack round-trip tests (`link.zig`, `root.zig`) are self-consistency tests
(encode with this module, decode with this module, assert equality) rather than independent-oracle
comparisons, and are documented as such.

## Threat model / out of scope

DNP3 (outside Secure Authentication) is an unauthenticated, unencrypted field protocol by design —
this module's job is robustness, not confidentiality/integrity against an active attacker. Hostile
or corrupt bytes from a misbehaving device or a MITM resolve to typed errors, never panics or
out-of-bounds reads, across every decode entry point (`link.decodeFrame`,
`transport.Reassembler.feed`, `application.decodeRequestHeader`/`decodeResponseHeader`,
`objects.decodeObjectHeader`, every `gNN.VN.decode`).

Out of scope for this pass: event object variations (g2 binary-input-event, g11/g13
binary-output-event, g22 counter-event, g32 analog-input-event, g42 analog-output-event, and
relative-time g50v2), file-transfer objects (g70), data-set objects (g85-g88 and related), the
unsolicited-response confirmation/retry timer state machine, and any actual transport (TCP/serial)
I/O — this module hands the caller bytes to send/receive, nothing more.

## g120 Secure Authentication hook (scaffold only)

`sa.zig` defines, but does not implement, the object shapes IEEE 1815's Secure Authentication
Annex / IEC 62351-5 rides on group 120 for: `Challenge` (v1), `Reply` (v2), `AggregateMac` (v9),
`SessionKeyStatus` (v5), `SessionKeyChange` (v6), and `SaError` (v7), plus the `HmacAlgorithm`,
`KeyWrapAlgorithm`, and `ErrorCode` enums those structs reference. Every `encode`/`decode` method
on those types is `@panic("TODO(agent): ...")` — this is the *one* place in the whole module that
panics on purpose, and the test suite deliberately never calls into it (a real call would abort
the test binary, which is exactly the point: an accidental production call fails loudly instead of
silently returning wrong crypto).

**Honesty on precision:** the variation numbers (v1/v2/v4/v5/v6/v7/v9) and algorithm-id values are
transcribed from secondary references (public DNP3 SA primers, the opendnp3 object model) rather
than a direct read of the primary IEEE 1815 SA Annex / IEC 62351-5 text, which wasn't available in
this environment. **The Fable crypto pass must cross-check every variation number, field width, and
algorithm-id value against the primary standard before any wire-level interop is attempted.** No
HMAC, AES-GMAC, AES key-wrap, or challenge/reply logic exists anywhere — that is the entire
deferred scope.

## Verification

51 offline tests (`zig build test-dnp3`, green in Debug + ReleaseFast; `zig fmt --check` clean).
Breakdown: `link` (11) — CRC catalogue + KAT vectors, control-octet round-trip, frame round-trips
(empty/short/multi-block/exact-16-byte-boundary user data), encode/decode error paths including a
malformed-input sweep; `transport` (9) — transport-octet round-trip, empty-fragment/single-segment/
multi-segment segmentation+reassembly, sequence-mismatch/continuation-before-FIR/FIR-restart/
buffer-too-small/empty-segment error paths; `application` (7) — app-control round-trip, IIN
round-trip, request/response header round-trips, `buildRequest`, short-fragment errors,
non-exhaustive function-code decode; `objects` (18) — qualifier byte round-trip, object-header
round-trips for every implemented range shape (1/2/4-byte start-stop, all-values, count+prefix,
4-byte count), range/qualifier-mismatch and value-out-of-range errors, a short/garbage decode
sweep, flags-byte round-trip, and an encode/decode round-trip for every core object
(g1v1 packed bits, g1v2, g12v1 CROB, g20v1/v2, g30v1/v2/v5, g40v1, g41v1/v2/v3, g50v1) plus a
short-record error sweep; `sa` (2) — the scaffold compiles with the right variation numbers and its
struct shapes construct without invoking any stub; `root` (4) — full link→transport→application
stack round-trips (single-frame and forced multi-frame >250-byte fragments) and a
master-builds-READ/outstation-parses + outstation-builds-RESPONSE/master-parses round trip.

## Backlog / deferred

- Byte-for-byte cross-check against a real captured DNP3 trace (Wireshark sample capture or a live
  opendnp3/pydnp3 session) — not done; see "CRC verification" above for what was and wasn't
  possible in this environment.
- Event object variations, file transfer, data sets — out of scope by design for this pass, not a
  gap in what was attempted.
- g120 Secure Authentication crypto (HMAC/AES-GMAC/key-wrap) — explicitly deferred to a future
  Fable pass; see the "g120 Secure Authentication hook" section above.
- A stateful `Master`/`Outstation` session type (confirm/retry timers, unsolicited-response state
  machine) — not part of this base-protocol pass.

## Status

`gap · any (pure codec, no I/O) · both (master+outstation via the same pure functions) ·
reentrant` + deps: none (std only) — canonical source is `pub const meta` in src/root.zig.

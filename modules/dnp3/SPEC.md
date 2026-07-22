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

68 offline tests (`zig build test-dnp3`, green in Debug + ReleaseFast; `zig fmt --check` clean).
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
short-record error sweep; `sa` (20) — AES-KW RFC 3394 §4.1/§4.3/§4.6 vectors + wrong-KEK/corruption
reject + malformed-length errors (integration tests through the shared `modules/aeskw` module, which
carries its own byte-exact KAT suite), HMAC-SHA-256 (RFC 4231) and HMAC-SHA-1 (RFC 2202) truncation KATs,
AES-GMAC (McGrew GCM test case 1) + compute/verify, constant-time verify accept/tamper/wrong-length,
g120 object-header + v1/v3/v4/v5/v6/v7/v9 codec round-trips, short/garbage decode sweep, session-key
wrap/unwrap (128- and 256-bit, wrong-update-key reject), the full challenge-response flow
(build v1 → compute v2 → verify accept; tamper MAC or ASDU → reject), and the `SeqCounter`/
`KeyExpiry`/`lookupUpdateKey` state helpers; `root` (4) — full link→transport→application
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

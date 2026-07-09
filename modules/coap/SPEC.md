# coap — spec

CoAP (RFC 7252) client/server stack: message codec, typed options, reliability, block-wise transfer,
observe. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
- **Layered, each independently testable:** `root` (C1) message codec — header/token/delta-encoded
  options/payload, `parse` (fills a caller option array; values borrow the datagram) /
  `serialize` (into a caller buffer) / `encodedLen`. `options` (C2) — the §5.10 option registry +
  §5.4.6 class bits + §3.2 CoAP-uint format + typed accessors + §6 URI↔options mapping.
  `reliability` (C3) — §4.2 CON retransmission with exponential backoff + deterministic jitter,
  §4.5 message-ID dedup window, empty-ACK/RST helpers. `client` (C4) — `buildRequest` +
  `Exchange.match` reply correlation. `server` (C5) — `isRequest` + piggyback/ackOnly/separate
  builders. `block` (C6, RFC 7959) — Block1/Block2 value codec (packed NUM:M:SZX), `split`,
  caller-storage `Assembler`. `observe` (C7, RFC 7641) — subscription `Registry` (Dedup-style
  bounded array + FIFO eviction), monotonic 24-bit `Sequence` + RFC 1982 lollipop `isNewer`; server
  push reuses `server.Server.separate` unchanged.
- **Zero-allocation, transport- and clock-agnostic:** codecs fill caller buffers; reliability and
  observe take the clock/sequence via caller state. Wire to any UDP/DTLS transport. Fully
  offline-testable.
- **Error policy:** malformed datagrams (bad TKL 9..15, option-number overflow, truncation, reserved
  SZX, oversized NUM) are typed errors, never panics.

## Threat model / out of scope
CoAP itself is unauthenticated/unencrypted on the wire; transport security is **DTLS, out of
scope** (the caller supplies the transport). The dedup window (§4.5) mitigates duplicate/replayed
message-IDs but is not an anti-replay security control. No congestion control beyond the §4.8
transmission parameters. Within C6, **combined Block1+Block2 in a single exchange** (RFC 7959 §3.3)
and **SZX renegotiation mid-transfer** are deliberately deferred (the assembler tolerates only a
constant block size).

## Verification
`zig build test-coap` — 55 offline tests. Codec (7): golden-byte CON GET round-trip, extended
option nibbles at the 13/269 boundaries, payload-marker edge cases, full parse/serialize error
matrix, `encodedLen` agreement. Options (19): class bits, uint codec boundaries + round-trip, typed
accessors, URI↔options mapping (percent-encoding, coaps, bad-scheme). Reliability (9): retransmit
schedule (jitter, full backoff to `timed_out`, `ack`/`onReset`, custom `max_retransmit`), dedup
window (fresh/duplicate/expiry/eviction). Client/server (7): request assembly + counter advance,
`Exchange.match` across all five reply kinds, `isRequest` gating, response builders, an end-to-end
client→server→client round-trip. Block-wise/Observe (12): Block codec edge cases, `split` boundary +
`Assembler` completion, two end-to-end block transfers (byte-exact 3000-byte Block2 GET reassembly;
Block1 PUT with `2.31 Continue`), Sequence wrap + lollipop comparison, Registry (freshness-checked
notify, FIFO eviction, re-register refresh), end-to-end observe register→notify→stale-reject→cancel,
CON-notification-timeout/RST cancellation glue. Green in Debug + ReleaseFast.

## Backlog / deferred
Combined Block1+Block2 in one exchange (RFC 7959 §3.3) and SZX renegotiation mid-transfer — both
documented in `block.zig`, not built.

## Status
`gap · any · util(codec)+client+server · reentrant` + deps: none (std only) — canonical source is
`pub const meta` in src/root.zig.

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
CoAP itself is unauthenticated/unencrypted on the wire. This module is transport-agnostic — the
caller supplies the datagram transport, and that transport can be **any** of: plain UDP, or a
caller-terminated **DTLS** session (RFC 7252 §9 / RFC 7641 §8's mandated CoAP transport security).
There is no CoAP-specific DTLS integration here — the same BYO-transport seam this repo uses for
BYO-TLS on TCP — so wiring DTLS is purely a matter of handing this module's `parse`/`serialize`
plaintext datagrams from/to whatever authenticated channel the caller already runs. **Production
CoAP over an untrusted network MUST run over that DTLS seam**; plain UDP is only appropriate on an
already-trusted link (e.g. a private network). No congestion control beyond the §4.8 transmission
parameters. Within C6, **combined Block1+Block2 in a single exchange** (RFC 7959 §3.3) and **SZX
renegotiation mid-transfer** are deliberately deferred (the assembler tolerates only a constant
block size, and rejects a mid-transfer SZX change with a typed error rather than mis-assembling).

Two further items were flagged in pre-public review as attacker-triggerable **on an unauthenticated,
connectionless UDP transport** and are now **addressed (admission hook + DTLS seam)** rather than
merely documented:

1. **Message-ID dedup window** (§4.5, `reliability.Dedup`) — caller-storage-bounded; an attacker who
   can inject packets can flood it with distinct message IDs to evict a legitimate exchange's entry
   before its retransmission window elapses, after which a replayed/retransmitted message with that
   ID is no longer recognized as a duplicate and is reprocessed. `Dedup`'s table size (the caller's
   storage slice) and remembered-duration (`lifetime_ms`) were already caller-configurable — a
   deployment sizes both for its expected authenticated-peer/exchange count — but sizing alone
   doesn't change what kind of control this is: **`Dedup` is a reliability control (duplicate
   suppression), not a replay-security control.** It becomes a security boundary only once the
   *source* is authenticated, i.e. run over the DTLS seam above, so that flooding one peer's window
   requires being that peer. See `reliability.zig`'s `Dedup` doc comment.
2. **Observe subscription registry** (§C7, `observe.Registry`) FIFO-evicts the oldest subscription
   when full. `Registry` now offers an **admission hook**: `admit_fn`/`admit_ctx` (type
   `observe.AdmitFn`, a plain function pointer + opaque context — no allocation, no closures) plus
   an optional **per-source cap** (`max_per_source`), both consulted by the new `Registry.tryRegister`
   entry point (the unconditional `register` primitive is unchanged, for callers that gate admission
   themselves or trust their transport). A hook that returns `false`, or a source at its cap, is
   rejected *before* the table is touched — no eviction of any existing entry. `source_id` is the
   caller's opaque peer identity; it is only a meaningful admission signal when it comes from an
   authenticated source (again, the DTLS seam) — a hook keyed off the unauthenticated UDP source
   address is not a mitigation, since that address is trivially spoofed. See `observe.zig`'s module
   and `Registry` doc comments for the full API and its `tryRegister` tests.

Both remain properties of *unauthenticated* CoAP, not bugs in this codec/state-tracking layer: the
hook and cap bound what an *admitted* or *uncapped* misbehaving source can do, but the real fix for
an untrusted network is DTLS (peer authentication) terminated by the caller, feeding a real
`source_id` and `admit_fn` policy into `Registry.tryRegister`.

## Verification
`zig build test-coap` — 65 offline tests. Codec (7): golden-byte CON GET round-trip, extended
option nibbles at the 13/269 boundaries, payload-marker edge cases, full parse/serialize error
matrix, `encodedLen` agreement. Options (20): class bits, uint codec boundaries + round-trip, typed
accessors, URI↔options mapping (percent-encoding, coaps, bad-scheme, a hostile Uri-Host escaped
rather than emitted verbatim). Reliability (10): retransmit schedule (jitter, full backoff to
`timed_out`, `ack`/`onReset`, custom `max_retransmit`), dedup window (fresh/duplicate/expiry/eviction,
zero-length storage never panics). Client/server (7): request assembly + counter advance,
`Exchange.match` across all five reply kinds, `isRequest` gating, response builders, an end-to-end
client→server→client round-trip. Block-wise/Observe (21): Block codec edge cases, `split` boundary +
`Assembler` completion (in-order assembly, a lone high-`num` final block rejected rather than
reported complete, a mid-stream gap rejected, a mid-transfer SZX change rejected), two end-to-end
block transfers (byte-exact 3000-byte Block2 GET reassembly; Block1 PUT with `2.31 Continue`),
Sequence wrap + lollipop comparison, Registry (freshness-checked notify, FIFO eviction, re-register
refresh), `Registry.tryRegister` admission policy (no-hook/no-cap parity with `register`, a rejected
hook neither registers nor evicts, an admitted source registers even table-full, a per-source cap
bounds one source's share without evicting), end-to-end observe register→notify→stale-reject→cancel,
CON-notification-timeout/RST cancellation glue. Green in Debug + ReleaseFast.

## Backlog / deferred
Combined Block1+Block2 in one exchange (RFC 7959 §3.3) and SZX renegotiation mid-transfer — both
documented in `block.zig`, not built.

## Status
`gap · any · util(codec)+client+server · reentrant` + deps: none (std only) — canonical source is
`pub const meta` in src/root.zig.

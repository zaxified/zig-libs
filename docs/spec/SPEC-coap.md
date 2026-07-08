# SPEC — `coap`

**Purpose** — CoAP (RFC 7252), the REST-over-UDP protocol of constrained / IoT devices, as a full
client/server stack: message codec, typed option layer, reliability, and the client/server request
paths. Pairs with `modbus`/`mqtt` for the industrial/IoT line-up.

**Model after / Seed** — clean-room from RFC 7252 (+ the URI mapping's RFC 3986 percent-encoding).
Greenfield — no seed; no third-party CoAP source (libcoap / aiocoap / Californium) consulted or
copied (NOTICE).

**Design & invariants**
- **Layered, each independently testable:** `root` (C1) message codec — header / token /
  delta-encoded options / payload, `parse` (fills a caller option array; values borrow the
  datagram) / `serialize` (into a caller buffer) / `encodedLen`. `options` (C2) — the §5.10 option
  registry + §5.4.6 class bits (Critical/Unsafe/NoCacheKey derived from the option number) + §3.2
  CoAP-uint value format + typed accessors + §6 URI↔options mapping. `reliability` (C3) — §4.2 CON
  retransmission with exponential backoff + deterministic jitter, §4.5 message-ID dedup window,
  empty-ACK/RST helpers. `client` (C4) — `buildRequest` (URI→options→datagram, sorted, token/mid
  counters) + `Exchange.match` reply correlation. `server` (C5) — `isRequest` + piggyback / ackOnly
  / separate response builders.
- **Zero-allocation, transport- and clock-agnostic:** codecs fill caller buffers; reliability takes
  the clock via a caller `now_ms`. Wire to any UDP/DTLS transport. Fully offline-testable.
- **Error policy:** malformed datagrams (bad TKL 9..15, option-number overflow, truncation) are
  typed errors, never panics.

**Threat model / out of scope** — CoAP itself is unauthenticated/unencrypted on the wire; transport
security is **DTLS, which is out of scope** (the caller supplies the transport). The dedup window
(§4.5) mitigates duplicate/replayed message-IDs but is not an anti-replay security control. **C6
block-wise (RFC 7959)** and **C7 observe (RFC 7641)** are deliberately deferred — large messages
beyond one datagram and resource observation are not yet supported. No congestion control beyond
the §4.8 transmission parameters.

**Verification** — Per-layer unit tests (C1 7 · C2 19 · C3 9 · C4 3 · C5 4): hand-built datagram
golden bytes, extended-nibble option boundaries (13/269), round-trip `parse∘serialize`, RFC 7252
class-bit table checks, retransmission/backoff schedule, dedup window, and an end-to-end
client↔server exchange.

**Status** — `gap · any · util(codec)+client+server · reentrant` · deps: none (std only).

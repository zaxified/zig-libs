# SPEC — `mqtt`

**Purpose** — A pure-Zig MQTT 3.1.1 client for the IoT / industrial (SCADA-sim) work: a typed,
allocation-free control-packet codec plus a transport-agnostic client state machine that drives the
full QoS 0/1/2 handshakes and is fully offline-testable. Pairs with `modbus`/`coap`.

**Model after / Seed** — clean-room from the OASIS MQTT Version 3.1.1 specification (open, royalty-
free). mosquitto (EPL/EDL) and Eclipse Paho are **behavior references only** — no source consulted
or copied (NOTICE). Greenfield, no seed.

**Design & invariants**
- **Three allocation-free layers:** `packet` — encode + decode for all 14 control-packet types
  (CONNECT/CONNACK, PUBLISH, PUBACK/PUBREC/PUBREL/PUBCOMP, SUBSCRIBE/SUBACK, UNSUBSCRIBE/UNSUBACK,
  PINGREQ/PINGRESP, DISCONNECT), with the remaining-length varint (1–4 bytes, max 268 435 455) under
  malformed/overlong guards and 2-byte-length-prefixed UTF-8 strings validated (U+0000 and bad UTF-8
  rejected). Decode is **zero-copy and stream-friendly**: `null` means "need more bytes". `topic` —
  `matches(filter, topic)` with the `+` single-level / trailing-`#` multi-level wildcard rules and
  the `$`-topic exclusion for leading wildcards, plus `validateName`/`validateFilter` (spec §4.7).
  `Client` — a client behind a caller-provided `Transport` write seam: `feed` takes incoming bytes,
  `poll(now)` decodes and advances the QoS state machines on both sides (QoS 1 PUBLISH→PUBACK, QoS 2
  PUBLISH→PUBREC→PUBREL→PUBCOMP, auto-acks, exactly-once receive dedup), surfacing typed events.
- **Bounded resources:** a packet-id pool (wrap 65535→1, in-use guard, typed exhaustion error); the
  rx buffer is bounded and overflow is a typed error.
- **Caller drives the clock:** every call takes `now` (ms) — no hidden time calls; `tick` sends
  keep-alive PINGREQ and reports ping timeouts. `publishDup` retransmits an unacked QoS>0 publish
  with the DUP flag. `TcpTransport` is an optional `std.Io.net` adapter — tests never dial.
- **Concurrency:** single-owner — one owner drives feed/poll/tick.

**Threat model / out of scope** — MQTT 3.1.1 carries credentials and payloads **in the clear**;
transport confidentiality/authentication is **TLS, which is out of scope** — the caller supplies the
transport (typically MQTT-over-TLS). The codec's guarantee is robustness: hostile broker bytes,
overlong varints, and bad UTF-8 all resolve to typed errors, never panics (fuzzed). **Out of scope:**
MQTT 5.0; the broker/server side; and retained-session persistence / offline-message replay
(buffering payloads across reconnects) is deliberately the caller's job.

**Verification** — 37 offline tests. Golden-byte KATs against the spec wire layout (CONNECT with will
+ credentials, CONNACK all return codes, QoS 1 PUBLISH round-trip preserving packet id, SUBSCRIBE/
SUBACK with mixed granted QoS incl. 0x80 failure, every remaining-length varint boundary with
overlong/5-byte rejection, empty-body packets). A scripted fake broker drives the full QoS 1 and
QoS 2 handshakes, DUP retransmit + receive dedup, keep-alive/ping timeout, packet-id wrap and pool
exhaustion, rx-buffer overflow. Plus a topic-match truth table and two 1000-iteration garbage-byte
no-panic sweeps (codec + client).

**Status** — `gap · any (codec+client pure; TcpTransport uses std.Io.net) · client+codec ·
single-owner` · deps: none (std only).

# mqtt — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Three allocation-free codec/client layers plus a broker, all offline-testable. `packet` — encode +
decode for all 14 control-packet types (CONNECT/CONNACK, PUBLISH, PUBACK/PUBREC/PUBREL/PUBCOMP,
SUBSCRIBE/SUBACK, UNSUBSCRIBE/UNSUBACK, PINGREQ/PINGRESP, DISCONNECT); remaining-length varint
(1-4 bytes, max 268435455) with malformed/overlong guards; 2-byte-length-prefixed UTF-8 strings
validated (U+0000 and bad UTF-8 rejected). Decode is zero-copy and stream-friendly: `null` means
"need more bytes". `topic` — `matches(filter, topic)` with `+`/`#` wildcard rules + `$`-topic
exclusion, plus `validateName`/`validateFilter` (spec §4.7). `Client` — behind a caller-provided
`Transport` write seam: `feed` takes incoming bytes, `poll(now)` decodes and advances the QoS state
machines (QoS 1 PUBLISH→PUBACK, QoS 2 PUBLISH→PUBREC→PUBREL→PUBCOMP, auto-acks, exactly-once
receive dedup); bounded packet-id pool (wrap 65535→1, in-use guard, typed exhaustion error); bounded
rx buffer (overflow is a typed error). Caller drives the clock — every call takes `now` (ms); `tick`
sends keep-alive PINGREQ; `publishDup` retransmits with DUP. Concurrency: single-owner (one owner
drives feed/poll/tick). `Broker` — the mirror image: owns the shared connection set, subscription
registry (flat, verbatim-filter, `topic.matches` per PUBLISH) and retained store; each `Connection`
is a reversed per-connection state machine (first packet must be CONNECT, client-id assigned or
rejected, session take-over on duplicate client-id, `session_present` always false — clean-session
only, keep-alive deadline = 1.5x client's keep-alive against a caller-supplied timestamp). PUBLISH
fan-out at min(publisher QoS, granted QoS), one copy per connection at highest granted QoS among
overlapping filters; QoS 0 fire-and-forget, QoS 1 inbound→immediate PUBACK, outbound→packet-id
allocated in the *subscriber's* id space tracked pending until PUBACK; retained store (empty
payload clears, delivered right after SUBACK). Same caller-driven socket-free seam as the client,
reversed; `TcpServer` is an optional `std.Io.net` accept loop (thread-per-connection, one spinlock
around the shared registry). Modeled after the OASIS MQTT 3.1.1 spec (open, royalty-free);
mosquitto/Paho are behavior references only — see NOTICE.

## Threat model / out of scope
MQTT 3.1.1 carries credentials and payloads in the clear; transport confidentiality/authentication
is TLS, out of scope for both client and broker — the caller supplies the transport (typically
MQTT-over-TLS, or `TcpServer` handed plaintext behind a TLS-terminating proxy). The codec's
guarantee is robustness: hostile broker/client bytes, overlong varints, and bad UTF-8 all resolve
to typed errors, never panics (fuzzed both directions). Out of scope: MQTT 5.0; retained-session
persistence / offline-message replay (buffering across reconnects, the caller's job); client-side
QoS 2 and DUP retransmit and Will/LWT are implemented, but the **broker's** first-cut deliberately
omits QoS 2 (an inbound QoS 2 PUBLISH is a protocol violation that tears the connection down),
persistent/offline sessions, DUP retransmit of an unacked outbound publish, and Will/LWT.

## Broker: not production-ready — known limitations
The broker is a functional first cut. It has been hardened against the trivial DoS/resource-
exhaustion vectors an early adversarial pass turns up first: the accept loop never runs a
connection handler inline on a failed task spawn (a stuck handler would otherwise wedge the whole
server), `Config.max_connections` / `max_subscriptions_total` / `max_subscriptions_per_conn` /
`max_retained` cap the shared connection set, subscription registry and retained store instead of
growing them unboundedly, a `SUBSCRIBE` over `max_filters_per_subscribe` is rejected as a whole
(never partial-registered then disconnected with no SUBACK), and a connection that opens a socket
but never sends CONNECT is dropped after `Config.connect_timeout_ms` instead of pinning a
slot/thread forever. It still requires the following work before it should face an untrusted
network:

- **PUBLISH fan-out is O(connections × subscriptions) under a single global spinlock** that
  `accept()` also takes (`handle`/`process` hold `Broker.mutex` for the whole fan-out loop). A
  large subscription set plus one PUBLISH can stall the entire broker — new connections, other
  clients' PUBLISH/SUBSCRIBE, everything — for the duration. Needs a real subscription index (e.g.
  a topic trie) and/or finer-grained locking before it can carry meaningful subscriber counts.
- **A QoS 0→QoS 1 re-encode for one subscriber can overflow that subscriber's `tx_buf`** (its
  own `max_packet_size`) — the packet id adds bytes the original QoS 0 publish didn't carry — and
  today that failure (`EncodeError.BufferTooSmall`, or `TransportFailed` if the write itself fails)
  is surfaced on the **publisher's** connection, because `deliver` runs inside the publisher's
  `process`/`handlePublish` call and its error propagates there — i.e. one small-buffered
  subscriber can get the *publisher* disconnected. Needs per-subscriber buffering/backpressure so
  one subscriber's delivery failure cannot take down an unrelated connection.
- **Session take-over does not close the superseded socket.** `takeover` drops the old
  connection's routing state and flips it to `.disconnected`, but the actual `std.Io.net.Stream`
  behind it is only closed when its own `TcpServer.connMain` notices (next read, next keep-alive
  check, or — pre-CONNECT/keep-alive-0 — never on its own). A client that reconnects with the same
  id while its old socket sits at `keep_alive_s == 0` leaks that thread/socket until the peer
  closes it or the process exits.
- **No authentication or ACL.** CONNECT `username`/`password` are decoded but never checked; any
  client that completes a CONNECT can publish or subscribe to any topic, including `$SYS`. There is
  no notion of per-client or per-topic authorization.

None of the above are addressed by this pass — they are architectural and need real design work
(subscription index, per-subscriber flow control, socket ownership on take-over, an auth/ACL
layer) rather than a bounded cap. Treat the broker as a functional first cut for trusted-network
use only until these are resolved.

## Verification
Client + codec: 37 offline tests (folded into the module total below) — golden-byte KATs against
the spec wire layout, every remaining-length varint boundary, a scripted fake broker driving full
QoS 1/QoS 2 handshakes, DUP retransmit + receive dedup, keep-alive/ping timeout, packet-id wrap +
pool exhaustion, rx-buffer overflow, a topic-match truth table, and two 1000-iteration garbage-byte
no-panic sweeps (codec + client). Broker: mirrors the same seam reversed — a scripted fake *client*
hand-encodes raw CONNECT/SUBSCRIBE/PUBLISH bytes against broker-side connection objects (no
socket): connect fan-in, subscribe→SUBACK→delivery, overlapping-filter single-copy fan-out,
retain-before-subscribe, QoS 1 PUBACK + broker-assigned delivery id, exact-string unsubscribe,
PINGRESP, DISCONNECT, keep-alive teardown, session take-over, and a 1000-iteration hostile-byte
no-panic sweep; `TcpServer` is compile-checked but gated behind `error.SkipZigTest` (not
socket-exercised). Run: `zig build test-mqtt`.

## Backlog / deferred
Broker: QoS 2, persistent/offline sessions, DUP retransmit of unacked outbound publishes, Will/LWT,
TLS, MQTT 5.0 (all documented deferrals, not bugs) — this was shipped as a "first cut"
(3.1.1/QoS0-1/clean-session/BYO-TLS) and **the broker (`broker.zig`, net-new conn state machine +
subscription registry + PUBLISH fan-out) is on the pre-public security/similarity review list**
(see /docs/pre-public-review.md) before any release — it has not yet had the adversarial pass the
client codec's fuzz sweeps stand in for. Client: MQTT 5.0 out of scope.

## Status
`gap · any (codec+client pure; TcpTransport uses std.Io.net) · client+codec · single-owner` + deps:
none (std only) — canonical source is `pub const meta` in src/root.zig.

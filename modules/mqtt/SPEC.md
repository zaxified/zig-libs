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
drives feed/poll/tick). `Broker` — the mirror image: owns the shared connection set, a **topic-filter trie** subscription
index (levels on `/`, `+`/`#` children, `$`-topic exclusion — matched only along a published topic's
path, never the whole set) and retained store; each `Connection` is a reversed per-connection state
machine (first packet must be CONNECT, client-id assigned or rejected, session take-over on
duplicate client-id which also shuts the superseded socket down, `session_present` always false —
clean-session only, keep-alive deadline = 1.5x client's keep-alive against a caller-supplied
timestamp). Optional auth + per-operation ACL hooks (function-pointer + opaque-ctx seam, default
allow-all). PUBLISH fan-out at min(publisher QoS, granted QoS), one copy per connection at highest
granted QoS among overlapping filters; QoS 0 fire-and-forget, QoS 1 inbound→immediate PUBACK,
outbound→packet-id allocated in the *subscriber's* id space tracked pending until PUBACK; retained
store (empty payload clears, delivered right after SUBACK). The global spinlock guards only short
registry mutations and the fan-out *snapshot* — never a socket write; each connection has its own
`tx_lock`, and fan-out readers reference-count targets so a mid-fan-out disconnect never writes to
freed memory; a per-subscriber delivery failure is contained to that subscriber. Same caller-driven
socket-free seam as the client, reversed; `TcpServer` is an optional `std.Io.net` accept loop
(thread-per-connection). Modeled after the OASIS MQTT 3.1.1 spec (open, royalty-free);
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

## Broker: production-hardened
The broker was a functional first cut hardened against the trivial DoS/resource-exhaustion vectors
first (the accept loop never runs a connection handler inline on a failed task spawn;
`Config.max_connections` / `max_subscriptions_total` / `max_subscriptions_per_conn` /
`max_retained` cap the shared connection set, subscription index and retained store; a `SUBSCRIBE`
over `max_filters_per_subscribe` is rejected as a whole; a connection that opens a socket but never
sends CONNECT is dropped after `Config.connect_timeout_ms`). The four remaining architectural
limitations have now been fixed:

- **PUBLISH fan-out no longer holds a global lock across I/O, and is no longer O(total
  subscriptions).** *(FIX A)* Subscriptions live in a **topic-filter trie** (`Index`): levels split
  on `/`, a `+` single-level-wildcard child, and `#` attached to the current node's `hash_subs`
  (also matching that node's own level, spec 4.7.1-2); the `$`-topic exclusion for a leading
  wildcard (spec 4.7.2-1) is honored by skipping the root's `plus`/`hash_subs` for a `$`-topic —
  exactly `topic.matches`'s rule (which the trie is truth-tabled against). Matching a published
  topic visits only nodes along that topic's path (bounded by the trie height, itself bounded by
  `max_filter_levels`), never the whole subscription set. `handlePublish` takes `Broker.mutex`
  **only** to update the retained store and snapshot the matching `(conn, granted-QoS)` set (one
  copy per connection at its highest granted QoS), then **releases it before any socket write**, so
  a large fan-out can no longer stall `accept()` or any other client. Each `Connection` carries a
  `tx_lock` guarding its `tx_buf` + packet-id pool + writes, so it can be written concurrently by
  many fan-out threads and its own owner thread without corruption or wire-interleaving. A fan-out
  reader takes a reference (`Connection.refs`) on each target under the global lock; `remove`
  unlinks a connection under the same lock (so no new reference can be taken) then drains
  outstanding references before freeing — a subscriber that disconnects mid-fan-out is never
  written to freed memory. (The global registry lock stays an atomic spinlock, as `std.Thread.Mutex`
  is gone in 0.16 and the offline core must not require an `Io`; it is simply never held across a
  socket write.)
- **A per-subscriber delivery failure is contained to that subscriber, never the publisher.**
  *(FIX B)* Fan-out delivery runs off the global lock, per subscriber, and any `EncodeError`/
  `TransportFailed` from one subscriber is caught: that subscriber is flagged `.disconnected` and
  its socket shut down for reaping, while fan-out continues to the others and the publisher's own
  PUBACK path is untouched. Each `tx_buf` is additionally sized `max_packet_size + tx_headroom` so a
  subscriber re-encode (which allocates a fresh packet id) always fits — no delivery can fail on
  buffer size at all. (With `min(publisher, granted)` QoS a delivered packet never exceeds the
  inbound one, so the failure now cannot arise from sizing; the containment guards residual
  transport failures.)
- **Session take-over closes the superseded socket.** *(FIX C)* `takeover` marks the old
  connection `.disconnected`, drops its routing state and now calls `Transport.close` (a socket
  *shutdown*, not a close) so a read loop blocked with `keep_alive_s == 0` wakes immediately and its
  owner thread reaps it via `remove` — no leaked thread/socket. `remove` drains fan-out references
  before freeing, and shutdown races safely with the owner's own `stream.close` (no double close of
  the fd).
- **Optional authentication + per-operation ACL.** *(FIX D)* `Config` gains an `authenticateFn`
  (+`auth_ctx`) invoked in `handleConnect` with the client id + username + password — a deny returns
  the proper CONNACK (`not_authorized` / `bad_username_or_password`) and closes; and an
  `authorizeFn` (+`acl_ctx`) checked in `handlePublish`/`handleSubscribe` with the client identity +
  topic + operation. A denied SUBSCRIBE yields per-filter SUBACK `0x80`; a denied PUBLISH is
  silently dropped (not retained, not fanned out) while the publisher is still PUBACKed. The
  authenticated username is threaded onto the connection so the ACL hook sees it. Both hooks are a
  clean function-pointer + opaque-ctx seam with **no external deps**; both default to null =
  allow-all (backward compatible).

Residual deferred scope (documented, not bugs): **QoS 2** (an inbound QoS 2 PUBLISH is a protocol
violation that tears the connection down), persistent/offline sessions (clean-session only), DUP
retransmit of an unacked outbound QoS 1 publish, and Will/LWT. TLS is out of scope by design
(terminate in front, or drive the socket-free core over a TLS stream). The concurrency hardening
targets the thread-per-connection `TcpServer`; the offline core remains single-owner per connection
and fully socket-free for testing.

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
no-panic sweep. The production-hardening fixes each carry a dedicated test: trie fan-out routing
across `+`/`#`/exact/`$SYS` subscribers (FIX A wildcard correctness); a lock-probe subscriber whose
write seam re-acquires the global spinlock — reaching the assertions proves the fan-out released the
lock before writing (FIX A no-lock-across-I/O); a failing subscriber transport contained so the
publisher is still PUBACKed and a healthy peer still delivered while the offender is dropped, plus a
max-size QoS 1 re-encode that does not overflow (FIX B); session take-over shutting the superseded
socket down (FIX C); and auth-deny (both CONNACK codes) + ACL-deny of PUBLISH and per-filter
SUBSCRIBE with the username threaded through (FIX D). `TcpServer` is compile-checked but never bound
in the offline suite.

**Multi-threaded stress / race pass (the concurrency hardening, exercised under real parallel load).**
A dedicated test stands up a real `TcpServer` on a loopback ephemeral port (`127.0.0.1:0`) and drives
it with **16 concurrent OS-thread clients over real sockets** (`std.Thread.spawn` clients; the broker
serves one handler thread per connection via `std.Io.Group.concurrent`, `concurrent_limit = .unlimited`
— genuine parallelism across cores). Each worker reconnects for many iterations in one of four
adversarial roles: (0) publisher hammering the hot namespace QoS0+QoS1 with interleaved unsub/resub
churn; (1) a subscriber that takes some fan-out then **abruptly closes its socket mid-fan-out** so a
broker write to it fails (FIX B containment); (2) a **take-over racer** that CONNECTs a shared
client-id concurrently with its peers (FIX C take-over socket-shutdown + zombie reaping under race);
(3) a slow reader doing heavy **subscribe/unsubscribe churn concurrent with fan-out** (FIX A
snapshot-under-lock + `refs` mid-fan-out UAF safety). Subscribers register overlapping `#`/`+`/exact
filters so each publish collapses to one copy per connection. Invariants asserted after the storm:
no crash/panic/UAF/double-free/leak (`std.testing.allocator` is a thread-safe DebugAllocator checking
every broker alloc/free from every handler thread); no deadlock/hang (a watchdog thread panics past a
90 s deadline, so a wedge fails the test instead of hanging CI); the accept loop never stalls behind a
fan-out (a liveness probe reconnects throughout and its CONNECT→CONNACK always completes within a
2 s bound); delivery still works end-to-end afterwards (a fresh sub+pub round-trips); no torn/corrupt
packet is ever decoded on a live stream; and once every client socket is closed the connection set
drains to 0 and `subscriptionCount()` to 0 (no take-over zombie, no leaked or wrapped-negative count).
The test is socket-gated (`error.SkipZigTest` on a single-threaded build or where loopback/threads are
unavailable), so a constrained `zig build test` stays green.

Race-detection method: Zig **0.16.0's `-fsanitize-thread` is a no-op** here — it compiles and links but
emits **zero `__tsan_*` instrumentation** and fails to flag a deliberate data race — so, per the SPEC's
own fallback, race detection is the real-thread run under **Debug and `-Doptimize=ReleaseFast`, repeated
(the committed 16×40 config was run 15× Debug + 40× ReleaseFast, plus one heavy 48×150 pass, all clean)**
and cross-checked with a **valgrind `memcheck` pass (0 errors, 0 leaks, no invalid read/write** — i.e. no
use-after-free in the reference-counted teardown). No race, deadlock, or UAF was found; the hardening is
confirmed. Run: `zig build test-mqtt` (also green under `-Doptimize=ReleaseFast`).

## Backlog / deferred
Broker: QoS 2, persistent/offline sessions, DUP retransmit of unacked outbound publishes, Will/LWT,
TLS, MQTT 5.0 (all documented deferrals, not bugs). The four architectural limitations of the first
cut — O(conns×subs) fan-out under a global lock held across I/O, publisher-killing per-subscriber
delivery failures, take-over socket leak, and missing auth/ACL — are now fixed (trie index +
snapshot-then-write off the lock + per-connection `tx_lock` + reference-counted teardown; contained
per-subscriber failures; take-over socket shutdown; optional auth/ACL hooks). **The broker
(`broker.zig`) was reviewed 2026-07-10 (adversarial security pass)** — varint/topic-matcher/
state-machine handling confirmed clean; the accept-loop inline-wedge DoS (CRIT) found in that pass
was fixed. The concurrency hardening's recommended
multi-threaded stress/race pass is now **COVERED** — see Verification above (16 real-socket
OS-thread clients racing fan-out / take-over / churn, run repeatedly under Debug + ReleaseFast and
under valgrind memcheck, all clean; TSan is a no-op stub in Zig 0.16.0, so real-thread stress is the
fallback). Client: MQTT 5.0 out of scope.

## Status
`gap · any (codec+client pure; TcpTransport uses std.Io.net) · client+codec · single-owner` + deps:
none (std only) — canonical source is `pub const meta` in src/root.zig.

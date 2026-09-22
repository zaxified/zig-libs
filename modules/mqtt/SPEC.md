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
duplicate client-id which also shuts the superseded socket down, clean and persistent sessions —
see *Persistent sessions* below, keep-alive deadline = 1.5x client's keep-alive against a caller-supplied
timestamp). Optional auth + per-operation ACL hooks (function-pointer + opaque-ctx seam, default
allow-all). PUBLISH fan-out at min(publisher QoS, granted QoS), one copy per connection at highest
granted QoS among overlapping filters; QoS 0 fire-and-forget, QoS 1 inbound→immediate PUBACK,
outbound→packet-id allocated in the *subscriber's* id space tracked pending until PUBACK; retained
store (empty payload clears, delivered right after SUBACK). The global spinlock guards only short
registry mutations and the fan-out *snapshot* — never a socket write. ⚠ That was **false for
SUBSCRIBE** until 2026-09-03: the retained walk ran once per filter in the packet, duplicates
included, snapshotting the whole store each time under the lock. Measured on a quarter-full default
store: 261 bytes in, 67 MB and 131 074 PUBLISH packets out, 3 s of one core with the lock held —
and `Broker.mutex` is a pure spinlock with no yield, so every other handler thread burns a core
waiting. The walk is now de-duplicated per packet and bounded by `max_retained_deliveries` /
`max_retained_bytes`; each connection has its own
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
sessions the broker itself persists (a server keeps them with `sessionStates`/`restoreSession`), and DUP retransmit to a clean-session subscriber. **Will/LWT is no
longer deferred** (2026-09-11): the broker keeps the will from CONNECT, publishes it on any
ungraceful end and discards it on a clean DISCONNECT (3.1.2.5, 3.14.4). The publish happens *after*
the connection has left the subscription index (2026-09-16, A1 M2), so the dying client is not
written its own Will; it still cannot happen under the registry lock, which `fanout` takes itself.
`Broker.publish` (2026-09-11) lets the server originate a message with no client behind it — same
retained-store and fan-out path, but no ACL call and no `onPublishFn` tap, since neither has a
connection to be about. It is held to `max_packet_size` like a receiver (2026-09-16, A1 M1): an
inbound PUBLISH cannot exceed that bound because `rx_buf` is exactly that size, and a
server-originated one that did used to return SUCCESS while disconnecting every matching
subscriber — and, with `retain`, kill every later subscriber at SUBSCRIBE. It now refuses
`error.PayloadTooLarge`.

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
  transport failures.) `error.Canceled` — the fan-out thread itself being canceled through the
  `std.Io` cancellation protocol, not a peer misbehaving — is deliberately **not** contained this
  way: containing it would flag every remaining subscriber in this publish's target set as failed
  and disconnect them for something none of them did. The fan-out loop instead releases its
  reference on every target and aborts the publish.
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
violation that tears the connection down), sessions the broker itself persists (they are in
memory; `sessionStates`/`restoreSession` let a server keep them), and DUP retransmit to a clean-session subscriber (a persistent one gets it on resume). TLS is out of scope by design
(terminate in front, or drive the socket-free core over a TLS stream). The concurrency hardening
targets the thread-per-connection `TcpServer`; the offline core remains single-owner per connection
and fully socket-free for testing.

## Persistent sessions (2026-09-21)
A CONNECT with clean session 0 gets a `Session` keyed by client id (spec 3.1.2.4): subscriptions,
a queue of QoS 1 messages, and up to `max_in_flight` sent-but-unacknowledged ones. Resume answers
`session_present = 1`, resends the in-flight messages with DUP and their original ids (4.4), then
drains the queue in order; clean session 1 discards the session (3.1.2-6).

Invariants and what holds each:
- **The session owns its subscriptions, not the connection.** The trie index refers to an `Owner`
  (a clean connection or a session), so a session's filters stay routable while no connection
  exists, and a park, resume or take-over moves no index entry — only `Session.conn`.
- **A QoS 1 message for a session is never lost to a disconnect racing its delivery.** Fan-out
  copies it into the session's queue *under the registry lock*, online or not; a pump holding the
  connection's `tx_lock` then moves it into flight and writes it. A connection that vanishes
  between snapshot and write leaves the message queued; a write that fails leaves it in flight, to
  go again with DUP on resume.
- **Nothing reaches a client before its CONNACK.** `handleConnect` holds the connection's
  `tx_lock` from before the session is attached until the CONNACK and every resent message are
  written, so a concurrent fan-out's pump waits.
- **Lock order: `Connection.tx_lock` → `Broker.mutex` → `Session.lock`**, and `Session.lock` is
  never held across a socket write — a message is encoded under it, written after it.
- **A superseded connection cannot edit a session.** `ownsRouting` refuses SUBSCRIBE/UNSUBSCRIBE
  from a connection that a take-over replaced, or whose session was discarded. ⛔ Found by the
  stress pass, not by review: without it an old connection still draining its receive buffer
  added a filter to a discarded session, which stayed in the index pointing at freed memory
  (SEGV in ReleaseFast, subscription count 126 against 26 in Debug).
- **Lifetime by reference count**: the registry, each connection carrying the session and each
  fan-out about to pump it hold one; the last to drop frees it.

Bounds: `max_sessions` (new past it → CONNACK `server_unavailable`; a resume always succeeds),
`max_queued_messages` / `max_queued_bytes` per session (overflow drops the newest, counted in
`queueDrops`), and `session_expiry_ms` applied by the caller's `expireSessions(now)`, since the
broker has no clock. QoS 0 is not queued (3.1.2.4 leaves it optional).

⚠ Not persisted by the broker: sessions are memory. A server that keeps them across its own
restart does it with two calls (2026-09-21): `sessionStates(arena)` copies out every session —
client id, subscriptions with their granted QoS, queued, in flight, and a per-session `drops`
count — under one lock, and `restoreSession(client_id, subs, now)` recreates one offline, all or
nothing, before clients connect. What goes back into the restored queue is the server's business
(its own replay source); the broker's part is the fact that makes that possible: a message is
queued by the `publish` that fans it out, so `queued + inflight == 0` at an instant means every
message published to the session before it has been acknowledged. `restoreSession` applies no
ACL (as `publish` does not — no client is asking) and refuses what no SUBSCRIBE could have been
granted: an invalid or too-deep filter, QoS 2, past `max_subscriptions_per_conn`/`_total`.

## Verification
**External anchor (`external_goldens.zig`).** Every KAT below this point is hand-authored from the
spec text and driven by a scripted fake peer — SPEC.md previously said mosquitto/Paho were
"behavior references only" and were never run. They now have been: real `paho-mqtt` bytes talking
to a real `amqtt` broker (both foreign) for a full CONNECT/SUBSCRIBE/PUBLISH-QoS-0/1/2/PING/
DISCONNECT session, a retained-message round trip, and a Will/LWT delivery on ungraceful loss; this
module's own `Client`, live, against real `amqtt` (QoS 0/1/2 + CONNECT-with-Will, byte-exact
encoder reproduction plus real-broker decode); and this module's own `Broker`, live, against real
`paho` (QoS 0/1 fan-out with the RETAIN bit correctly cleared on a live delivery — a case no prior
offline test asserted — retain-before-subscribe, and the documented QoS-2-tears-the-connection-down
behavior against a genuine client). A real, reported (not "fixed") finding: `amqtt` does not perform
the spec 3.3.5 QoS-downgrade-on-delivery that this module's own `Broker` does. ⚠ The captures
**cannot** anchor our own downgrade: every publish in them has publisher QoS equal to granted QoS,
so §3.3.5 is never exercised and mutating `minQos` away leaves all eight golden tests green. Only
the in-tree test catches it. Genuine anchor, no discrimination on that property — see the file's
doc comment. See the file's doc
comment for capture provenance and attribution (root `NOTICE` §0 — black-box oracle, no source
consulted).

Client + codec offline tests — golden-byte KATs against
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

**Persistent sessions** have 16 offline tests (resume with `session_present`, queue while away,
socket death without DISCONNECT, clean-session discard, DUP resend with the original id, a failed
write kept in flight, QoS 0 not queued, both queue bounds, the in-flight window refilled by
PUBACK, persistent and clean take-over, `max_sessions` without a stray Will, expiry, retained QoS 1
through the queue, `deinit` with queued and in-flight messages), plus 4 for keeping them across a
server restart (`sessionStates` of online and offline sessions with a drop, a restored session
queueing and resumed, `restoreSession` refusals leaving nothing, expiry from the restore). 16 guards were removed one at a
time on 2026-09-21 and each turned a test red (runner deleted afterwards, CONVENTIONS §9). The
stress pass runs its upper half of workers on persistent sessions — resuming on most reconnects,
discarding with a clean CONNECT on every third — and asserts after the storm that every
remaining subscription is a session's, every session is offline and holds exactly the registry's
reference. Run 10× ReleaseSafe and 20× ReleaseFast clean; with `ownsRouting` removed it failed 5
of 5. ⚠ The valgrind pass below predates sessions and has not been repeated for them. (A run over
the Debug build was made and is not evidence either way — CONVENTIONS §7.1: nothing measured under
valgrind may be a Debug build.)

Race-detection method: Zig **0.16.0's `-fsanitize-thread` is a no-op** here — it compiles and links but
emits **zero `__tsan_*` instrumentation** and fails to flag a deliberate data race — so, per the SPEC's
own fallback, race detection is the real-thread run under **Debug and `-Doptimize=ReleaseFast`, repeated
(the committed 16×40 config was run 15× Debug + 40× ReleaseFast, plus one heavy 48×150 pass, all clean)**
and cross-checked with a **valgrind `memcheck` pass (no errors, no leaks, no invalid read/write** — i.e. no
use-after-free in the reference-counted teardown). No race, deadlock, or UAF was found; the hardening is
confirmed. Run: `zig build test-mqtt` (also green under `-Doptimize=ReleaseFast`).

## Backlog / deferred
Broker: QoS 2, sessions persisted across a broker restart, DUP retransmit to clean-session subscribers,
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

**Broker hooks — two gaps (from the egw-hub audit, 2026-09-22):**
- `AclRequest` has no `retain` flag. A retained PUBLISH to a command topic
  cannot be denied by the ACL, only refused in `onPublishFn` (which closes the
  connection). Mosquitto's ACL check sees it (`mosquitto_acl_msg.retain`).
  egw-hub today: `hubTap` refuses a retained command (`egw-hub/src/loop.zig`,
  `acl_mod.isCommand`). Ideal: `AclRequest.retain: bool` (false for SUBSCRIBE).
- `PublishVerdict` has only `accept` (store + fan-out + PUBACK) and `refuse`
  (no PUBACK, close). A PUBLISH that is a command to the broker's host
  (a request answered on another topic) needs a third answer: PUBACK, but no
  retained store and no fan-out. egw-hub today moved its request topics out of
  every consumer's filters instead (`egw-hub/history/…`, audit B9). Ideal:
  `.consume`.

## Status
`gap · any (codec+client pure; TcpTransport uses std.Io.net) · client+codec · single-owner` + deps:
none (std only) — canonical source is `pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/external_goldens.zig freezes real MQTT 3.1.1 sessions captured through a byte-logging proxy between paho and amqtt -- neither side ours -- covering CONNECT/PUBLISH/SUBSCRIBE and the RETAIN bit; broker.zig session state and topic.zig matching stay self

**How it got there.** The anchoring work landed. DONE 0b466d6: 9 real paho/amqtt sessions both directions; amqtt itself violates 3.3.5

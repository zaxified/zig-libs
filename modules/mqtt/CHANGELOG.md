# mqtt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-11** — `Connection.keepAlive()` and `Connection.willOpt()`. Both are things a *bridging*
  consumer needs and could previously only get by reaching into fields: the keep-alive so the two
  halves of one logical connection do not time out on different schedules, and the Will because a
  mirror that omits it leaves the far side believing the client is online for ever. `willOpt`
  returning null is also the gracefulness test the Will machinery already relies on internally — it
  is null after a clean DISCONNECT (3.14.4) — so exposing it hands consumers the same signal rather
  than a second, weaker one. ⚠ The slices are the broker's owned copies and die with the connection;
  a consumer that replays them must copy. ⭐ The password is deliberately NOT added to `Connection`:
  a consumer that must authenticate onward as the client already receives it in `AuthRequest`, and
  holding every client's secret for the lifetime of its session to save that is a poor trade.
  Measured RED → GREEN with three mutations.

- **2026-09-11** — ⛔ **The broker did not compile for a 32-bit target at all**, and nothing here
  could see it. Four counters (`fanout_truncations`, `retained_truncations`, `qos1_drops`,
  `will_failures`) were `std.atomic.Value(u64)`, and a 32-bit target has no 64-bit atomic
  read-modify-write without libatomic — so `@atomicRmw` on one is a *compile* error,
  `expected 32-bit integer type or smaller`. They are `usize` now: exactly "the widest this
  platform can increment atomically", and wrapping is not a concern for counters of failures and
  truncations. The stress harness's `probe_max_ms` went the same way, to `u32`. Found by the first
  consumer to cross-compile this module (a store-and-forward proxy, ARMv7 in a router container),
  not by any gate: every lane in this repo builds native x86-64, where the whole file looks fine.
  ⭐ So the module now **declares `.linux32`** (mips32 soft-float, big-endian) in `meta.targets`,
  which puts `portable-mqtt-linux32` — the test binary *and* the forcing root that references every
  non-generic public declaration — between that class of defect and the next consumer. Measured:
  restoring any one of the four counters to `u64` turns that gate red, each on its own.
  ⚠ A first attempt at a guard was a `zig build-obj` of the module root for ARM; it passed with the
  defect restored, because an object build of a root nothing references analyses no bodies — the
  blind spot `check-portable`'s own design comment already names. The repo's instrument was right
  and a second one was not needed.

- **2026-09-11** — **`Broker.publish`: the server can originate a message.** Until now the broker
  could only relay — every byte it put on a wire came from some other client's PUBLISH — and
  `Connection.lockedWrite` is private, so a consumer had no way to say anything of its own at all.
  That leaves out every server that *has* something to say: a bridge injecting the other side's
  traffic, a gateway answering a device's configuration request, a `$SYS` topic, a fixture seeding
  a retained value. The spec describes the Server as a sender of Application Messages (3.3) and
  nowhere requires that one arrived from a Client first. The message takes the client path exactly:
  retained store (3.3.1.3, empty payload clears), then fan-out at `min(qos, granted)`, one copy per
  connection, a failed subscriber contained to itself. Two deliberate differences, both because
  there is no client here to be one: **no ACL call** (`aclAllows` answers "may *this connection*
  publish here"), and **the tap does not fire** — `onPublishFn` observes what the broker accepted
  *from its clients*, and feeding a server's own message back would make a bridge echo itself.
  Held to the same topic rules as an inbound PUBLISH (4.7.1: no wildcards, no U+0000, non-empty),
  and QoS 2 is refused rather than silently downgraded. `fanout` lost its publisher parameter,
  which it had never read. Driven by the first outside consumer (a store-and-forward proxy): the
  device behind it subscribes to its clock configuration topic and then waits, and without a clock
  it publishes no measurements at all. Measured RED → GREEN: five mutations — tap fired, topic unvalidated, QoS 2
  admitted, retain dropped, granted QoS ignored — each kill exactly the test that names them.

- **2026-09-11** — **Will / LWT is implemented in the broker**, closing what SPEC.md carried as
  deliberately deferred first-cut scope (3.1.2.5, 3.1.3.3, 3.14.4). The will registered at CONNECT
  is kept as owned copies — the decoded slices point into the receive buffer and the next packet
  overwrites them — published on *any* ungraceful end (dead socket, protocol violation, keep-alive
  expiry, session take-over) and discarded on a clean DISCONNECT, which is what makes "a will is
  still set" the test for an unannounced end. A will topic carrying a wildcard is refused as a
  protocol violation rather than a CONNACK code: none of 3.2.2.3's codes describes it, and the
  nearest one would send a client hunting through its client id for a fault in its will topic.
  An undeliverable will is counted by the new `willFailures()` rather than lost silently — the
  teardown path has no caller to return an error to. Driven by the first outside consumer
  (a store-and-forward proxy), whose device sets a will and whose proxy must replay it upstream.
  Measured RED → GREEN: four separate mutations (no publish on loss, no discard on DISCONNECT,
  no topic validation) each kill exactly the test that names them.

- **2026-09-11** — `Config.onPublishFn`: an optional observer of every PUBLISH the broker accepts,
  called after the ACL verdict and before fan-out. Null by default; it cannot affect routing.
  `authorizeFn` could not serve — `AclRequest` carries the topic but not the payload, and returns a
  verdict rather than observing — so the only way to obtain a message was to register a loopback
  subscriber and re-decode the broker's own output, which costs a connection's buffers and reads
  as a puzzle. The topic and payload slices are valid only for the duration of the call.
  Measured RED → GREEN, and the refused-publish direction is asserted too: a publish the ACL
  denied is not observed, while the publisher is still PUBACKed as before.

- **2026-09-10** — The over-long-username gap recorded below (2026-09-03) is fixed: `handleConnect`
  now refuses a CONNECT whose username exceeds `max_username` (256 B) with CONNACK
  `bad_username_or_password` and closes, instead of silently leaving `has_username` false. P1
  (no consumers in this repo): input hardening needed no sign-off. Measured RED → GREEN by
  reverting the guard to the old "store if it fits, else do nothing" shape and rerunning
  `test-mqtt`: 76 pass / 1 skip / **1 fail** (the new refusal test — `expected .close, found
  .keep`), vs. 77 pass / 1 skip / 0 fail with the fix restored.
- **2026-09-07** — Fuzz reach: `packet.fuzzDecode` never called `decode`. It opened with
  `smith.bytes(&buf)` and then `smith.valueRangeAtMost(u16, 0, buf.len)`; a ranged draw reads
  eight octets as a little-endian u64 and returns the range MINIMUM when fewer than eight
  remain, and `bytes` had already consumed the seed — so `len` was **0 on every input**, and
  `len` here is the bound of `while (off < len)`, the reader loop. The body never executed. The
  harness's own comment claims it "advances over a stream the way a real reader loop would";
  the aim canary beside it (`fuzzDecode's stream walk is reachable and correct`) was the only
  thing keeping that claim honest, and it walks its own bytes rather than the harness's. The
  draw is now one `smith.slice(&buf)`, and the corpus is built by this module's own encoders:
  eight real streams (including the four-packet canary stream and its one-octet-short form,
  CONNECT with will/username/password, a QoS-2 PUBLISH) plus ten named refusals. Measured
  2026-09-07: **0 of 18 seeds reached `decode` and 0 packets were walked before, 18 of 18 and
  18 packets after.** A corpus guard pins both numbers.

- **2026-09-03** — Drift re-audit (window `e5594e8..HEAD`, +1174/-36 over 9 files). Six findings.

  - **CRITICAL, one 261-byte packet.** `handleSubscribe` re-ran the whole retained-store walk once
    per filter entry, and `registerSubscription` correctly returns true for a repeated filter
    (§3.8.4-3 makes it a QoS update). Every match was `dupe`d into one list held simultaneously,
    and the whole thing ran inside the global lock. So one SUBSCRIBE carrying `#` sixty-four times
    — 261 bytes, well under `max_packet_size` — made the broker snapshot the store 64 times over.
    Measured on a **quarter**-full default store: **67 MB and 131 074 PUBLISH packets out, 3 s of
    one core**, lock held throughout. `Broker.mutex` is a pure spinlock with no yield, so every
    other handler thread burns a core for the duration; and §3.8.4 requires re-sending retained
    messages on every subscribe, so it is repeatable at will by any client that may publish and
    subscribe — which, with the default `Config`, is every client. Fixed by de-duplicating the walk
    per packet and bounding it: `max_retained_deliveries` (8192 — one full pass over a `max_retained`
    store, so ordinary use is never truncated) and `max_retained_bytes` (16 MiB), with
    `Broker.retainedTruncations()` as the observable signal. Same probe after the fix: 1.05 MB and
    2050 packets in 61 ms — exactly one legitimate pass.

  - **HIGH (doc/anchor), the external captures cannot anchor the QoS downgrade they are credited
    with.** `external_goldens.zig`'s doc comment said the `paho_vs_zig_broker` capture "shows
    byte-exact correct downgrade behavior against a real client". Every publish in it has publisher
    QoS equal to granted QoS — `min(0,0)` and `min(1,1)` — so §3.3.5 is never exercised: mutating
    `minQos(pub_pkt.qos, t.qos)` to `t.qos` leaves **all eight golden tests green**, and only the
    in-tree test goes red. The captures are genuine, and their RETAIN-clearing teeth are the only
    thing in the module that catches that bit. Genuineness and discrimination are separate
    properties; the doc claimed the second from the first.

  - **LOW, `connTimeoutMs` could wrap negative.** `connect_timeout_ms` is a `u32`; above
    `maxInt(i32)` (~24.8 days, a legal value) the `@intCast` panicked in Debug and wrapped negative
    in ReleaseFast, which `poll(2)` reads as "block indefinitely" — pinning the handler thread and
    the `max_connections` slot of a connection that never sends CONNECT, i.e. exactly the wedge the
    timeout exists to prevent. Now clamped.

  - **LOW, a silent QoS 1 drop with no signal.** A subscriber whose in-flight pool is full silently
    lost every further message. Counted now (`Broker.qos1Drops()`); non-zero means a subscriber has
    stopped answering PUBACKs.

  - **LOW, `max_fanout_matches` is inert at its default.** It equals `max_subscriptions_total`, and
    `Index.collect` can never gather more refs than there are subscriptions, so the envelope cannot
    bind until an operator lowers it. The doc framed that as a benefit; it now also says it provides
    no protection as shipped, and that the truncation's first-match-wins trie order deterministically
    starves whoever sorts late.

  - **LOW, the fuzz harness barely reached the stream behaviour it advertises.** 256 uniform random
    bytes are malformed at packet one, so the multi-packet walk was essentially never exercised.
    Added an aim canary that drives the same loop over real back-to-back packets and asserts it
    walked all of them.

  Also recorded, not fixed: an over-long username is silently **not retained**, so `authenticateFn`
  and `authorizeFn` see `username == null` for that connection rather than the credential the client
  sent — an ACL treating `null` as anonymous is reachable by sending an over-long username.


- **2026-08-22** — Both `client.TransportError` and `broker.TransportError` gained a
  `Canceled` variant so a `std.Io` cancellation (`Future.cancel`) surfaces distinctly
  from `TransportFailed`; `broker.Error` gained the matching variant.
  `client.TcpTransport.readSome` used to read via a raw `std.posix.read` — not a
  registered `std.Io` operation, so a cancel could never reach a thread parked in it
  at all — and now routes through `std.Io.net.Stream.Reader` instead, recovering
  `Canceled` from the concrete reader's `err` field like the write side already did.
  `broker.TcpServer`'s per-connection `waitReadable` had the same class of gap in its
  `std.posix.poll`-based read timeout (EINTR-restarting, uninterruptible by a cancel
  signal that is never even sent) and its own read loop; both now check
  `io.checkCancel()` / route through `std.Io.net.Stream.Reader`. The PUBLISH fan-out
  no longer treats its own thread being canceled as a per-subscriber delivery failure
  (a canceled broker is not a misbehaving subscriber) — see `SPEC.md`. Added
  `root.BrokerTransportError` alongside the existing `root.BrokerTransport` for
  symmetry with the client-side aliases.
- **2026-08-14** — Provenance record completed: Eclipse Paho was named as a design
  reference without its licence, and mosquitto's was given as the informal
  "EPL/EDL"; both are EPL-2.0 or EDL-1.0 and now say so, as `/NOTICE` §0
  requires. Nothing is owed either way — a design reference imposes no
  condition. Documentation only.

- **2026-07-19** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Per-type mandatory
  fixed-header flag bits (PUBREL/SUBSCRIBE/UNSUBSCRIBE = 0b0010, all others = 0)
  enforced (`packet.zig:592-596`).
- **2026-07-07** — New module: MQTT 3.1.1 client — all 14 control packets, QoS 0/1/2
  state machine, topic-filter wildcards, transport-agnostic seam.

# mqtt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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

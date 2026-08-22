# mqtt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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

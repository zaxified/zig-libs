# mqtt — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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

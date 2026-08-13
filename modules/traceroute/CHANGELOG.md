# traceroute — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: no findings. Modeled on `traceroute(8)` / `mtr`
  (design reference, not a test anchor).
- **2026-07-07** — New module: ICMP-echo path discovery — TTL-stepped probes, per-hop
  address + RTT stats, load-balanced-path aware.

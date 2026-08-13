# rawsock — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: no findings. Modeled on `libpcap` (minimal AF_PACKET
  path) (design reference, not a test anchor).
- **2026-07-09** — New module: Linux AF_PACKET raw-frame capture + inject — BPF filter,
  promiscuous mode, typed frame decode.

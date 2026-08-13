# ipcbus — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on varlink / D-Bus (unix control
  sockets); a hand-rolled length-prefixed unix RPC (design reference, not a test
  anchor).
- **2026-07-09** — New module: Same-host unix-socket control plane — request/reply
  server + a capped in-memory scratch key→bytes bus.

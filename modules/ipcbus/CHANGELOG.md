# ipcbus — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-05** — Mutation run: 25 of 25 killed, 0 equivalent; 7 tests added
  (`CLOEXEC` on every fd, stale-path replace and unlink on `deinit`, one-byte
  transport and `readExact` EOF, `FdWriter.drain` splat and count, `handleOne`
  closing its fd, `clear` bumping `version`, `Bus.set` under allocation
  failure). No code change.
- **2026-07-19** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on varlink / D-Bus (unix control
  sockets); a hand-rolled length-prefixed unix RPC (design reference, not a test
  anchor).
- **2026-07-09** — New module: Same-host unix-socket control plane — request/reply
  server + a capped in-memory scratch key→bytes bus.

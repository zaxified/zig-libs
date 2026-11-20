# ipcbus — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-18** — **Behaviour change:** `Server.acceptOne` now checks the peer's `SO_PEERCRED` uid against a `PeerPolicy`; the default (`Server.listen`) admits only the server's own effective uid, like the D-Bus session bus (`EXTERNAL` auth: the identity is a Unix user taken from kernel-passed credentials). A refused peer is closed silently, counted in `Server.refused`, and `acceptOne` keeps waiting (it never returns an error for a refused peer, so a non-admitted local user cannot stop an accept loop that ends on `catch return`). Added `PeerPolicy` (`.same_uid`, `.uids = &.{..}`, `.any`), `Server.listenWithPolicy`, `Server.policy`/`own_uid`/`refused`. Opt out of the check with `Server.listenWithPolicy(path, .any)` (the previous behaviour). Security-triage row ipcbus:92. Delta mutation: 15/15 killed; one test added (the refused-peer fd is closed even when its credentials cannot be read).

- **2026-11-16** — **Added:** optional timeouts and peer credentials. `Options{ .timeout_ms }` with `Client.requestWithOptions` and `Server.handleOneWithOptions` (one monotonic deadline over the request/reply I/O, polled; a silent or stalled peer returns `error.Timeout`, never a hang; `request`/`handleOne` keep blocking forever). `peerCred(fd)` returns `PeerCred{pid,uid,gid}` (`SO_PEERCRED`); new `TransportError.Timeout` and `.PeerCredFailed`. `FdReader`/`FdWriter` gain deadline fields (default off). No behaviour change for existing callers.


- **2026-10-23** — **Fix (performance):** `FdReader` refills its buffer on small reads. Zig 0.17's `defaultReadVec` streams straight into the caller's slice once the buffer has been filled to its end, so a long-lived reader paid one `read(2)` per frame-length prefix. Regression test with a negative control. No API change.

- **2026-10-18** — Ported to Zig 0.17.0. test helper `bufPrintZ` -> `bufPrintSentinel`. Also: comptime `strRepeat` helper quota raised.
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

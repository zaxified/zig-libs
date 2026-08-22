# ssh — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — `server.zig` and `connection.zig`'s test-only `acceptBounded` (the
  `poll(2)`-bounded accept wait every self-interop/live-interop test goes through) now
  recovers a `std.Io` cancellation. `std.posix.poll` retries on `EINTR` and a thread
  parked in it is never signalled by `Threaded` at all, so a canceled accept wait used to
  run to its full timeout and come back as `error.AcceptPollFailed` or
  `error.PeerNeverConnected` — indistinguishable from a poll failure or a peer that
  genuinely never connected. Each file's `acceptBounded` now calls the new local
  `checkCanceled` once the wait ends, on both exit paths, and surfaces `error.Canceled`
  instead. `transport.zig` needed no change — it takes a caller-supplied `Io.Reader`/
  `Io.Writer` and owns no fd (documented at its `Transport.init` in the prior commit); the
  fd this module actually owns is the listening socket behind `acceptBounded`, which is
  test infrastructure only, not part of the module's public API. Two tests cover it (one
  per file); both were confirmed to fail (`error.PeerNeverConnected` instead of
  `error.Canceled`) with the recovery reverted.
- **2026-08-13** — `meta.platform` corrected `.any` → `.linux`. No code change: the
  transport's `getrandom(2)` entropy loop already `@compileError`ed on every non-Linux
  target (verified by cross-compiling the suite to macOS, Windows and FreeBSD), so the
  old tag advertised portability the module never had. README platform lines follow.
- **2026-08-11** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against RFC
  4253 §7.2.
- **2026-07-10** — New module: SSH-2.0 (RFC 4253) client + server transport.

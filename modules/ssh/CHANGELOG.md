# ssh — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — New public field `Transport.negotiated` (`transport.NegotiatedAlgorithms`):
  the KEX/host-key/cipher/MAC wire names KEXINIT actually negotiated (RFC 4253 §7.1),
  client and server side. Before this, `clientHandshake`/`serverHandshake` computed these
  as local variables and dropped them — a caller had no way to reproduce `ssh -v`'s
  negotiation banner, which both Go's `ssh.ConnMetadata` and russh's `check_server_key`
  callback expose. Sweep of the whole handshake path (client + server) found no other
  dropped negotiated parameter worth exposing the same way (the peer's raw version-
  identification string is also currently dropped, but exposing it needs `Transport` to
  own allocated memory, a materially bigger change, left open). Lifetimes: every field
  resolves to one of this module's own `pub const` name-list entries, or (server-side host
  key) a `HostKey.algorithmName()` literal — never a slice into a peer-parsed `KexInit`'s
  name-list, which is `gpa`-freed once the handshake that decoded it returns. Fixing this
  on the server side required also fixing `server.zig`'s private `pickFirst`, which
  previously returned the match from the *client's* (freed-on-return) name-list rather
  than from this module's own static one — harmless while its result was used only
  inside `serverHandshake`, but exactly the dangling-pointer shape `NegotiatedAlgorithms`
  cannot tolerate once held past the function returning. Proven with new assertions
  against a real `sshd`/`ssh` (the existing live OpenSSH interop tests, both files):
  observed to fail (16/100 tests, exactly the live-interop ones) with the two
  `t.negotiated = ...` assignments reverted, pass restored (100/100) — Debug, ReleaseSafe
  and ReleaseFast.
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

# procrun — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-17** — The documented "compiles for Windows" claim was false, and had been
  since the module existed: `spawnChild` passed the POSIX literal `0` to `Child.pgid`
  ("lead your own group"), which on Windows is a `?*anyopaque` HANDLE and does not
  typecheck, and the `statusToTerm` test decodes a POSIX wait(2) status word through
  `std.posix.W`, which is `void` there. Both are now branched at `comptime`
  (`new_process_group` was already documented as a Windows no-op, so the branch keeps
  that promise rather than failing the build). No behavior change on POSIX. Nothing in
  this repo compiled for Windows, which is why a false claim survived — and `check-portable`
  would not have caught it even with a Windows target, because `build-obj` on a library root
  analyses no function bodies at all (measured: reverting qr's 32-bit fix leaves
  `zig build portable-qr` green).
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Python
  `subprocess.run`/`Popen`, Go `os/exec` (design reference, not a test anchor).
- **2026-07-09** — New module: Subprocess runner: reap-race-tolerant wait, deadlock-free
  capped stdio capture, timeout, streaming + cancel.

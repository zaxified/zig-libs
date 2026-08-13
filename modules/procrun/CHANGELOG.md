# procrun — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Python
  `subprocess.run`/`Popen`, Go `os/exec` (design reference, not a test anchor).
- **2026-07-09** — New module: Subprocess runner: reap-race-tolerant wait, deadlock-free
  capped stdio capture, timeout, streaming + cancel.

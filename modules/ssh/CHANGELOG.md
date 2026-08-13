# ssh — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — `meta.platform` corrected `.any` → `.linux`. No code change: the
  transport's `getrandom(2)` entropy loop already `@compileError`ed on every non-Linux
  target (verified by cross-compiling the suite to macOS, Windows and FreeBSD), so the
  old tag advertised portability the module never had. README platform lines follow.
- **2026-08-11** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against RFC
  4253 §7.2.
- **2026-07-10** — New module: SSH-2.0 (RFC 4253) client + server transport.

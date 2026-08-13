# syslog — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  5424 §6.5's published test vectors.
- **2026-07-09** — New module: RFC 5424 syslog formatter + emitter, RFC 3164 legacy
  encoder, RFC 6587 TCP octet framing.

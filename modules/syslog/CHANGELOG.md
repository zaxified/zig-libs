# syslog — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — `zig build check-fuzz` exemption: `**Fuzz exemption:** EMIT-ONLY`
  recorded in SPEC.md. This module formats and sends syslog messages and has no
  receiver/parser in its public surface (already documented in the module doc and
  `meta.role = .client`); the one byte-accepting public function
  (`writeOctetCounted`'s RFC 6587 framer) only ever length-prefixes this module's own
  formatted output, never bytes read off a socket or out of a file.
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  5424 §6.5's published test vectors.
- **2026-07-09** — New module: RFC 5424 syslog formatter + emitter, RFC 3164 legacy
  encoder, RFC 6587 TCP octet framing.

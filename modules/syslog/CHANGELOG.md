# syslog — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — `TcpEmitter.send` now returns the explicit `TcpEmitter.SendError`
  (`NoSpaceLeft`, `WriteFailed`, `Canceled`) instead of an inferred `!void`, and
  recovers `Canceled` from the concrete `std.Io.net.Stream.Writer`'s out-of-band
  `err` field before falling back to `WriteFailed` — a `std.Io` cancellation
  (`Future.cancel`) mid-write is now distinguishable from a real transport failure.
  `UdpEmitter.send` needed no change: `Socket.SendError` already carries
  `Io.Cancelable` directly, with nothing narrowing it away. No blocking-write test
  was added — each `send` call is bounded to the module's own small formatted
  message (well under any realistic kernel socket buffer), so it does not actually
  block against the established loopback test probe; forcing a block would need
  artificial socket-buffer starvation outside that probe's shape, which was not
  fabricated. There is no blocking read path in this module at all (emit-only).
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

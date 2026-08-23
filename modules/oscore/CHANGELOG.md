# oscore — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — Added `OscoreOption.encodePartialIv`, the minimal-length
  big-endian Partial IV encoding `encode()` already used internally, now
  public. Found writing the consumer example: `AadParams.request_piv` (§5.4)
  must carry a request's own Partial IV in this exact wire form, but a
  caller protecting its own request has no `Protected.option.partial_iv`
  bstr to read it back from before calling `protect` — this module's own
  README usage sample worked around the gap with `&.{@intCast(seq)}`, which
  truncates (and panics in Debug/ReleaseSafe) for any sequence number
  `>= 256`. `encode()` now calls the same helper instead of duplicating the
  logic inline; README fixed to use it.
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Byte-exact against RFC 8613
  Appendix C's published test vectors.
- **2026-07-12** — New module: OSCORE — Object Security for Constrained RESTful
  Environments (RFC 8613) — end-to-end object security for CoAP: §3.2.1 HKDF-SHA-256
  security-context derivation.

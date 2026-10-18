# `b64ct` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-18** — Ported to Zig 0.17.0: comptime `strRepeat` branch quota scaled with length.
- **2026-10-17** — New module: constant-time base64 (RFC 4648 standard and
  URL alphabets, padded and unpadded) for secrets, replacing the private
  `b64ct.zig` copies in acme, dns, smtp and megolm. libsodium's decoder
  contract (strictness, `ignore`, `b64_end` as `decodePrefix`), PEM/MIME
  `encodeWrapped`, `decodeInPlace`, allocating helpers; a 16-lane decode path.
  Verified against RFC 4648 §10, `std.base64` (tests + fuzz) and libsodium
  1.0.22's `codecs.c` live (`tools/interop.zig`, 300 000 cases, 0 differences);
  ctgrind 0 in-file contexts.

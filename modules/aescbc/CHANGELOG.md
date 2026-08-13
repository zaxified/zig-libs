# aescbc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Byte-exact vs NIST SP800-38A
  Appendix F.2.1 (AES-128-CBC) and F.2.5 (AES-256-CBC), *both directions independently
  asserted*.
- **2026-07-22** — New module: raw AES-CBC (NIST SP800-38A, over `std.crypto.core.aes`)
  + PKCS#7 / XML-Enc padding helpers; zero-alloc core, padding-oracle caveat documented
  (consumers own authenticate-before-unpad).

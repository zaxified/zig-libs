# ocsp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: seven findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against a
  live capture from OpenSSL `OCSP_basic_verify` / `OCSP_check_validity`
  (`crypto/ocsp/`).
- **2026-07-22** — New module: RFC 6960 OCSP — build an OCSPRequest and parse +
  cryptographically verify an OCSPResponse.

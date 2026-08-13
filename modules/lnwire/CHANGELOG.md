# lnwire — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: five findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against BOLT#1 Appendix A/B's
  published BigSize/TLV test vectors.
- **2026-07-21** — New module: Lightning BOLT#1/2/7 wire messages (the message codec
  that rides on `bolt8`'s encrypted transport).

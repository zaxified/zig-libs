# xmldsig — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Genuinely
  external, five committed fixtures in `src/test_external.zig` produced offline by
  `xmlsec1` (C/OpenSSL) and `signxml` (pure Python, shares no code with either):.
- **2026-07-22** — New module: XML Canonicalization (exclusive/inclusive C14N ±comments,
  `InclusiveNamespaces` PrefixList) + XML-Signature verification (xmldsig-core 1.1).

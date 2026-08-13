# xml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Genuine
  external oracle — the vendored W3C XML Conformance Test Suite
  (`src/testdata/xmlconf/`, driven by `src/xmlconf_test.zig`): 25 `not-wf` reject
  vectors + 105.
- **2026-07-21** — New module: namespace-aware, security-hardened XML 1.0 parser →
  C14N-ready infoset tree.

# xml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — **`Options.max_elements` (default `1 << 20`) and
  `error.TooManyElements`: a bound on BREADTH.** `max_depth` bounded nesting and said
  nothing about how wide a document may be, and a flat document is the cheap shape —
  `<a/>` is four source bytes per element and builds an `Element` plus its children and
  attribute slices. Measured in ReleaseFast, peak LIVE bytes of `parse` alone: 64 KiB of
  source → 6,339,414 B (96.7x), 256 KiB → 32,177,512 B (122.7x), 1 MiB → **163,139,946 B
  (155.6x)** — and superlinear, so a caller that bounds the SOURCE has not bounded the TREE.
  Found from the consumer end: `saml`'s HTTP-Redirect binding capped the inflated octets at
  1 MiB and reached ~163 MB from a 1,496-byte query string, before authenticating anything.
  The default is generous for every document this repo parses (a SAML response is hundreds
  of elements) and caps the worst case near 160 MB instead of leaving it open; a caller
  facing untrusted input should set it far lower, as `saml` now does (8192).
  ⚠ **Additive but not invisible:** a consumer parsing a genuinely enormous document will
  now see `error.TooManyElements` where it previously succeeded, and an exhaustive `switch`
  over `ParseError` does not compile until it handles the new variant.

- **2026-08-06** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Genuine
  external oracle — the vendored W3C XML Conformance Test Suite
  (`src/testdata/xmlconf/`, driven by `src/xmlconf_test.zig`): 25 `not-wf` reject
  vectors + 105.
- **2026-07-21** — New module: namespace-aware, security-hardened XML 1.0 parser →
  C14N-ready infoset tree.

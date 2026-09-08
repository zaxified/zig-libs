# xml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — Docs: `src/xmlconf_vectors.zig` carried two NOTICE pointers and both were
  wrong. `../../NOTICE` resolves to `modules/NOTICE`, which has never existed; and the second
  one described the root file as "the root-level attribution index", which it stopped being on
  2026-09-06. `../NOTICE` is now the whole answer. No code or data changed.
- **2026-09-07** — **`fuzzParse` ran one input for ever, and its byte-biasing
  loop had never executed.** It opened with `smith.bytes(&buf)` followed by
  `smith.valueRangeAtMost(u16, 0, buf.len)`; `bytes` consumes
  `min(buf.len, in.len)` octets and the ranged draw then reads eight *more* as a
  little-endian u64, returning the range minimum when fewer remain — so the drawn
  length was 0 for every input a seed can carry. The loop that remaps bytes onto
  XML's own syntax alphabet iterates `buf[0..len]`, so with `len == 0` it never
  ran either: the paragraph above the harness promising a byte pool biased toward
  `<>/="'&;` was describing code that had not executed. With no corpus the target
  replayed `parse("")`, which is rejected on the first byte. Now one
  `smith.slice(&buf)` draw and a 16-document corpus (prolog, CDATA, every
  predefined entity and both numeric forms, namespace declarations, comments and
  PIs, multi-byte UTF-8, plus the duplicate-`ID` signature-wrapping refusal,
  invalid UTF-8, a non-UTF-8 encoding declaration, XML 1.1 and four truncations).
  The biasing stays for `--fuzz` and the guard pins that it is inert on a replay,
  because a biasing loop that DID fire would corrupt every seed into a syntax
  error. Measured 0 accepted / 0 elements before; 16 seeds, 0 mangled bytes,
  7 accepted, 12 elements built after.
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

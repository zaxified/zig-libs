# xml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 fix campaign (audit `A1/xml.md`, five findings closed):
  - **F1 (HIGH)**: `Element.inScopeNamespaces` was O(k^2) in the number of
    in-scope namespace declarations (rescanned everything collected so far
    per declaration), reachable pre-authentication through `xmldsig`'s
    inclusive C14N at the apex. Rewritten around a `StringHashMapUnmanaged`
    seen-set, O(k). Measured (ReleaseFast, single call): 102,400
    declarations dropped from 6,485 ms to 11.5 ms, 563x, with the same
    output set and order as before (pinned by a dedicated regression test
    written and verified against the OLD body first). The allocation
    contract changes: the function now allocates a temporary map, freed
    before returning.
  - **F5 (MED, partial)**: `Element.textContent` no longer recurses on the
    machine stack — rewritten around an explicit heap stack, same allocator
    the function already took, no signature change. Measured (Debug): the
    old recursive body SIGSEGV'd at depth 200,000 (200,000 nested elements
    around one text leaf); the new body succeeds past 1,000,000.
    `Document.findByAttr`/`findByAttrRec` has the identical recursion shape
    and remains open — fixing it needs either a new allocator parameter or
    an internal fallback allocator, both bigger than this fix and requiring
    a decision this module's fixer brief reserves for the user.
  - **F2 (MED)**: `Options.max_elements`'s own doc comment claimed the
    worst case stays "around 160 MB"; measured directly at the cap
    (367,223,862 B, ~350 MiB) and corrected the comment. No behaviour
    change.
  - **F8 (LOW)**: `findByAttr`'s doc comment recommended it for
    "signature-wrapping-safe lookup" without stating that, unlike
    `getElementById`, it has no duplicate detection. Rewrote both doc
    comments to say what each function actually guarantees. No behaviour
    change (`xmldsig` already enforces uniqueness itself rather than
    relying on this function for it).
  - **F9 (LOW, five of seven mutation-testing gaps)**: M03, M15, M19, M24
    and M27 were all already handled correctly by the parser (three
    unchanged since the module's first commit) — the mutations the audit
    ran against a copy survived only because no test pinned the behaviour.
    Added targeted regression tests for all five; no code changed. M13 is
    left as documented-but-imperfect (the existing surrogate test already
    explains why it cannot fully distinguish the mutation at its one
    reachable call site). M16 (invalid UTF-8 inside a Name is not
    rejected, unlike in text/attribute values) is a live gap, not a test
    gap — left open, now named in SPEC.md's "Out of scope" section.
  - **SPEC.md**: named five findings that stay open because closing them
    changes observable parse behaviour (accepting or rejecting input this
    parser does not today) — F3 (CR normalization skips comments/PIs), F4
    (lenient non-ASCII Name acceptance), F7 (inconsistent `xml`-target PI
    reservation), F9 "M16" above, and F10 (`.ignore` DOCTYPE skip mishandles
    a literal `>` inside a quoted external identifier). No behaviour
    change; SPEC.md now says what the parser actually does.
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

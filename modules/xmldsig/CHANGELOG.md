# xmldsig — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz reach: `fuzzVerifySignature` ran one fixed document, forever. Its
  FIRST draw was `smith.value(bool)` (`allow_weak_sha1`), and a `Smith` scalar or ranged
  draw returns the range minimum when fewer than eight octets remain; with no corpus the
  single input it ever ran was empty, so all ~20 of its choices collapsed —
  `allow_weak_sha1` false, `id_attr` null, all three algorithm picks index 0, both
  transforms absent, no second reference, no KeyInfo cert, every buffer all-zero. ⚠ Mode 2
  is the sharp one: its whole point is "a genuinely VALID signed document with a
  fuzzer-chosen byte range overwritten", and `n = @min(smith.valueRangeAtMost(u8, 0, 32),
  …)` was **0**, so it verified the PRISTINE document and reached the digest and signature
  comparisons with nothing changed. The neighbouring reachability test asserts that path
  IS reached — correctly — and cannot see that nothing was ever mutated on it. Mode 3 got
  `raw_len` = 0 and verified the empty string. Measured 2026-09-07: 1 round, 0 octets
  mutated, 0 unstructured octets. The harness draws a SHAPE, not a byte string, so it now
  reads every choice out of one byte-first `smith.slice` through `testkit.fuzz.Cursor`,
  over eight scripts of which the first is the EMPTY one, reproducing the collapsed
  harness exactly. The mutation moved into `mutateDoc` so the guard measures the same
  generator the harness runs. ⚠ The guard pins octets overwritten, not "verify was
  reached": Pinned: 4 scripts with `allow_weak_sha1` on, 120 unstructured octets, 33
  octets mutated — all three were 0.

- **2026-09-03** — Drift re-audit. **The `<ds:Reference>` loop is bounded, in
  both directions.** It ran with no cap on the reference COUNT and allocated
  every reference's canonical form from the `verify` arena, which is released
  only on return — so `R` references held `R` full canonical copies at once,
  and `URI=""` makes each copy the whole document. The loop runs BEFORE the
  `SignedInfo` signature is checked (it has to: the digests are what the
  signature covers), so none of that work needed a key or a valid signature,
  and `saml` reaches it from an unauthenticated POST-binding `<Response>`.
  Measured in ReleaseFast: **286 KB of garbage-signed XML with 2000 references
  → 2.67 GB resident and 7.8 s of CPU**, 9323x amplification, quadratic. Now
  `Options.max_references` (default 8; a real SAML assertion has one), counted
  and refused BEFORE the canonicalization it would pay for, plus a
  per-reference arena reset so the peak is one canonical copy rather than `R`
  — measured on an 8-reference document: **89 180 bytes before, 12 602 after**.
  Both halves are pinned by their own test.
- **2026-09-03** — **`URI=""` is refused when the document carries prolog or
  epilog nodes this module cannot canonicalize.** `URI=""` is the whole
  DOCUMENT node-set; canonicalization starts at `doc.root`, so a processing
  instruction outside the root element was outside the digest while the caller
  was told the whole document was signed — an attacker could inject
  `<?...?>` into a validly signed document and it still reported `valid`.
  Confirmed against xmlsec1 on this module's own committed fixture: xmlsec1
  answers `FAILED / reason: REFERENCE` for the bytes we accepted. ⚠ Refused,
  not covered: `xml.Document` does expose `prolog`/`epilog`, so covering them
  properly is possible and is the right end state, but it needs C14N's own
  prolog/epilog newline rules and should be diffed against `xmllint --c14n`.
  Refusing is fail-closed and cannot forge. Not reachable through `saml`,
  which requires `#id`.
- **2026-09-03** — **`c14n` bounds its own recursion** (`Options.max_depth`,
  default 256, typed `error.MaxDepthExceeded`). `writeElement` recurses on the
  machine stack and the only bound was the `xml.Options.max_depth` the document
  was parsed with — an explicitly supported knob, and `xml`'s own parser keeps
  its stack on the heap, so raising it was safe for `xml` and a SIGSEGV here.
  Measured in ReleaseFast on an 8 MiB stack: depth 32 000 canonicalizes, depth
  36 000 crashes (exit 139); in Debug the crash arrives between 4 000 and
  8 000. SPEC's "no input path panics" was false for such a caller. `saml`
  handles the new error at its three call sites.
- **2026-09-03** — Four advertised guards that no test pinned now have tests;
  each mutation below previously left `test-xmldsig` AND `test-saml` fully
  green, because a corpus of valid signatures cannot exercise a refusal: the
  RSA-SHA1 *signature*-method downgrade gate (only the `DigestMethod` half was
  covered), the external-reference refusal (replacing it with `return doc.root`
  made an `http://` reference silently canonicalize the local document), the
  "at least one Reference" check (a zero-reference signature reported
  `valid = true` — a signature covering nothing), and all three algorithm
  allow-lists (only the *transform* one was pinned; a silent default is an
  algorithm-confusion primitive).
- **2026-09-03** — Docs: README's quick-start ended at `if (!result.valid)` and
  the example's banner promised "what a SAML relying party does" — both taught
  the signature-wrapping bug by omission. `result.valid` says a signature
  verified, not that it covered the element the caller trusts. README now
  carries that as step 4 and the example says plainly that it does not
  demonstrate it.
- **2026-09-03** — ⛔ **Recorded, NOT fixed.** `countByAttr` and `findX509Cert`
  in `root.zig` recurse on the machine stack in the same shape `c14n` just
  bounded, differing only in that their depth is the document's rather than a
  canonicalization's. The `EXTERNAL anchor` reproduction recipe in `root.zig`
  does not reproduce as written (both constants ARE genuine and were
  re-derived; the recipe omits removing `<ds:Signature>` for the reference
  digest and extracting the `SignedInfo` subtree with its own `xmlns:ds`). The
  fuzz harnesses enter 2 and 6 times respectively per deterministic run.


- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Genuinely
  external, five committed fixtures in `src/test_external.zig` produced offline by
  `xmlsec1` (C/OpenSSL) and `signxml` (pure Python, shares no code with either):.
- **2026-07-22** — New module: XML Canonicalization (exclusive/inclusive C14N ±comments,
  `InclusiveNamespaces` PrefixList) + XML-Signature verification (xmldsig-core 1.1).

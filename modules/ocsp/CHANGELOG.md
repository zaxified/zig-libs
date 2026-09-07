# ocsp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Test-only, two harnesses.** (a) `fuzzParseResponse` drew
  `smith.bytes(&buf)` and then `smith.valueRangeAtMost(u16, 0, buf.len)`;
  `bytes` consumes `@min(buf.len, in.len)` octets, so the ranged draw found
  fewer than the eight it reads as a little-endian `u64` and returned the
  range MINIMUM — `len` was 0 and `parseResponse` was handed the empty slice
  for every input the ordinary test lane can carry. ⭐ Its buffer was also
  **512 octets against a delegated response of over 800**, so even with the
  draw fixed no response carrying its own responder certificate — the shape a
  real responder returns — could have passed through, since a seed longer than
  the buffer reads back EMPTY rather than truncated. One `smith.slice` now,
  buffer 512 → 4096, and a 13-seed corpus whose accepting entries are built at
  run time from this module's own DER writer. Measured 2026-09-07: **0 of 13
  seeds non-empty, 0 octets and 0 responses parsed before; 12, 2172 octets, 4
  parsed and 3 carrying a decoded BasicOCSPResponse after.**
  (b) `fuzzVerify` was a structured harness whose choices came from a chain of
  ranged `Smith` draws with a `verifySeed(mode, bits, n)` helper writing each
  as its own little-endian `u64` word. That worked, but every seed was an
  opaque word list, and widening any range past a word hand-chosen for the old
  one would silently collapse that draw with the suite still green. The
  choices now come out of one `smith.slice` read through
  `testkit.fuzz.Cursor`, so a seed is a reviewable octet script.
  ⭐⭐ Fixing the draw exposed a second dead knob of the same family as the
  `now_unix` one this harness already carries a warning about: `damage` drew
  its offset with `smith.index(buf.len)`, **one octet**, so it could only ever
  damage the first 256 octets of a response over 800 — the whole
  `tbsResponseData` past that, and the signature over it, were out of reach of
  the `DamagedResponseAccepted` assertion. Offsets are 16-bit now, and one
  corpus seed damages at offset 320 deliberately. A new deterministic guard
  pins the number of rounds on which that assertion is ARMED (mode 1 **and**
  `damage` actually changed an octet): **5 of 12 seeds**, with one seed
  flipping the same octet twice on purpose so the guard measures `damage`'s
  return value and not the seed count.

- **2026-09-03** — Drift re-audit (695 lines since the last one). The drift's own
  security work holds: five one-line mutants against the `IssuerMismatch` check,
  the anyEKU strictness, `DigestCache` algorithm keying, `unknown` vs `good` and
  the `issuerNameHash` conjunct all die. What follows is what it did not cover.
  - **A verified response was not byte-unique.** A single bit flipped at each
    offset in turn over an 848-byte response: **14 offsets still verified
    `good`**. All of them lie outside `tbsResponseData`, so the signature cannot
    object — only the parser can, and it did not. Ten were this module's:
    container LENGTH octets never checked for exact closure (the `[0] EXPLICIT`,
    `ResponseBytes`, the response OCTET STRING, `BasicOCSPResponse`, the `certs`
    wrapper), the `05 00` NULL parameters of the response's own
    `signatureAlgorithm`, and the signature BIT STRING's unused-bits octet, which
    DER requires to be zero and which was never read. All fixed, with a test that
    re-runs the whole sweep and pins the boundary.
  - **The fuzz harness asserted exactly this and the assertion was DEAD.** Its
    comment reads "a response altered anywhere must not verify", but the damage
    mode also randomized `now_unix`, so the freshness check rejected nearly every
    damaged input before the assertion could be reached. Pinning the clock — one
    change — made it fire in 287 coverage-guided runs, on the real defect above.
    The clock is pinned for that mode now, and the assertion is scoped to what
    this module is answerable for.
  - ⛔ **Recorded, not fixed:** the remaining malleable octets are the `05 00`
    NULL parameters inside the embedded delegate CERTIFICATE, parsed by
    `x509`/`std.crypto.Certificate`. The fix belongs there. The new test excludes
    exactly that range and says so, so closing it will make the test red and it
    can then be tightened to zero.
  - Docs: SPEC.md's generated Anchoring line said "responses self-signed
    fixtures" two lines above the record that real DigiCert and GoDaddy captures
    had landed; its mutation-teeth paragraph carried stale counts ("exactly the
    three … all nineteen"; measured: 5 and 25 — the claim survives, the numbers
    did not); and this changelog credited "a live capture from OpenSSL
    `OCSP_basic_verify` / `OCSP_check_validity`", which are functions, not a
    capture.

- **2026-08-06** — Security audit: seven findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). ⚠ This entry used to
  end "Verified against a live capture from OpenSSL `OCSP_basic_verify` /
  `OCSP_check_validity` (`crypto/ocsp/`)" — those are OpenSSL *functions*, and nothing
  was captured from them; the audit ledger names them as the C-reference **competitor**
  for the algorithm-parity comparison. The real anchors are live DigiCert and GoDaddy
  responses plus OpenSSL-signed fixtures. The same template sentence appears in at least
  three other module changelogs, so the generator is what needs fixing, not just this line.
- **2026-07-22** — New module: RFC 6960 OCSP — build an OCSPRequest and parse +
  cryptographically verify an OCSPResponse.

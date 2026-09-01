# x509 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-01** — **Security audit: the DER guard did not guard, in three
  separate ways.** `safe.zig` advertised `safeCertificate` as returning a
  certificate "safe to hand to `std.crypto.Certificate.parse` without any risk
  of panic, out-of-bounds read, or segfault regardless of optimisation mode".
  It was not, and the argument in `SPEC.md` that said so was unsound.

  `walk` descends into **constructed** elements; `Certificate.parse` descends
  into an element's content by **field position**, whatever the constructed
  bit says. Nine bytes exploit the difference: `30 07 04 05 30 83 01 00 00` is
  a `SEQUENCE` holding a primitive `OCTET STRING` whose content declares 65536
  bytes. It passed the guard, and std then indexed at offset 65545 — abort in
  Debug, segfault in ReleaseFast. Reshaped, the same trick made `parse` return
  **successfully** with a `pub_key_slice` ending 172 bytes past the buffer,
  which the caller hands to a signature verifier as key material. `parse_slack`
  cannot help: an attacker-chosen 32-bit length is not a boundary probe.
  `requireStdDescentPoints` now requires a constructed element at every
  position std descends into, which is what carries the tiling proof over to
  std's walk. It runs in `safeCertificate`; `validateCertificate` keeps the
  narrower well-formedness contract and its doc no longer claims otherwise.

  Third shape, needing no primitive at all: an **empty BIT STRING**. std's
  `parseBitString` reads the unused-bits octet without checking one exists and
  returns `start + 1` regardless, so `03 00` yields a slice whose start is one
  past its end. Here the padding made things *worse* — it satisfied the
  unguarded read, so instead of aborting loudly the corruption surfaced
  downstream as a 4 GB `Parsed.signature()` in ReleaseFast. X.690 §8.6.2.3
  requires that octet, so `walk` rejects the encoding.

  Reachable from `iec62351`'s TLS profile, `opcua`'s `SenderCertificate`
  handling, `webauthn`'s `x5c[0]` and `dtls`'s anchor check — all peer bytes.

- **2026-09-01** — **`chain.zig` had the same BIT STRING defect and does not
  use the guard at all.** `parseShape` calls std's `parseBitString` on the
  SubjectPublicKeyInfo and signatureValue elements, both attacker-controlled.
  `verifyChain` reaches the first of them via `buildPath` on the peer's leaf
  certificate **before any signature is checked**, and `verifyMlDsaLink` /
  `verifySlhDsaLink` / `verifyPssLink` each call `parseShape` as their first
  statement. Now routed through a local `parseBitStringSafe`; two regression
  tests drive a crafted certificate through the public `verifyChain` and abort
  the test binary when the guard is removed.

- **2026-09-01** — **The public single-link PQ helpers now chain the issuer's
  name.** `verifyMlDsaLink` and `verifySlhDsaLink` checked the parameter set,
  both lengths, the validity window and the signature, but not RFC 5280
  §6.1.3 (a)(4) — so an issuer whose subject DN is not the subject's issuer DN
  was accepted. `verifyChain` was never affected (path building only offers
  candidates whose subject matches), but the doc comment invites direct use and
  their std counterpart `Parsed.verify` makes the check. Ordered after the
  parameter-set comparison so an algorithm mismatch is still reported as one.

- **2026-09-01** — **Three checks the SPEC said were pinned by tests, and were
  not.** SPEC claimed each of the ML-DSA path's four checks went red when
  removed; the key-length and signature-length comparisons did not, and the
  SLH-DSA validity window had no test while SPEC called the two paths "the
  same shape". They guard slice-to-array coercions, so in ReleaseFast their
  absence is an out-of-bounds read of up to 4627 bytes fed into verification.
  Tests added by renaming a real certificate's algorithm OIDs rather than by
  DER surgery — SHA2-128s and SHA2-128f share a key length and differ only in
  signature size, which is what makes the signature-length check expressible.

- **2026-09-01** — **Docs: the name-constraint gap fails CLOSED, not open.**
  `chain.zig`, `root.zig` and `SPEC.md` all described an unmatchable
  `GeneralName` type (`rfc822Name`, `uniformResourceIdentifier`) as a
  fail-*open* bypass. Since the `constraintTypeSupported` change both the
  excluded and the permitted side reject. The real exposure is the opposite
  one and was undocumented: a CA carrying an rfc822Name constraint turns away
  every subordinate certificate with an rfc822Name SAN, including one inside
  the permitted subtree.


- **2026-08-22** — **SLH-DSA (RFC 9882) certificates verify — all twelve FIPS
  205 parameter sets.** `x509.verifySlhDsaLink` joins the ML-DSA path added
  the same day; the module gained a `slhdsa` dependency, since std has no
  SLH-DSA at all (unlike ML-DSA, where only the X.509 *name* was missing).
  This is what owning the OID table bought: the algorithm is one table entry
  and one dispatch arm, not a redesign.

  The parameter-set check carries more weight here than for ML-DSA. `s` and
  `f` share a public-key length, and the two hash families at the same
  security category share both lengths — so SHA2-128s against SHAKE-128s is
  distinguished from a forged signature by the set comparison alone.

  Coverage is two-tier and stated rather than implied: two full OpenSSL 3.5.5
  hierarchies (one per hash family) plus one self-signed certificate per
  parameter set — a self-signed certificate is a link whose issuer is itself.
  Twelve full hierarchies would be 1.2 MB of fixtures to re-prove path
  building eleven more times. All fourteen certificates were accepted by
  `openssl verify` at generation time.

- **2026-08-22** — **ML-DSA (RFC 9881) certificates verify.** `verifyChain`
  now accepts ML-DSA-44/65/87 links and leaves, via the new
  `x509.verifyMlDsaLink` and std's `std.crypto.sign.mldsa`. The obstacle was
  never the cryptography, which std already had: `std.crypto.Certificate`'s
  OID table is an exhaustive enum with no seam to extend, so a certificate
  signed with an OID std does not carry fails at `Certificate.parse` with
  `error.CertificateHasUnrecognizedObjectId` before anything is verified. The
  new `x509.algorithm` is this module's own table — it consults std's first
  and passes std's answers through unchanged, so nothing that verified before
  resolves differently. Cross-checked against three full OpenSSL 3.5.5
  hierarchies (one per parameter set), each accepted by `openssl verify` at
  generation time.

- **2026-08-22** — **Breaking:** `VerifiedChain.leaf` is now
  `?std.crypto.Certificate.Parsed`, and two fields joined it: `leaf_der` (the
  leaf's bytes, always present) and `leaf_pub_key_algo` (this module's own
  algorithm union, which unlike std's can name every algorithm this module
  verifies). `leaf` is null exactly when std cannot parse the leaf at all —
  RSASSA-PSS, and now ML-DSA and SLH-DSA — because `Parsed.signature_algorithm` is an
  exhaustive enum with no variant for either, so any value there would be a
  wrong answer a caller could not distinguish from a right one.

  This is also a fix: a PSS-signed **leaf** previously failed `verifyChain`
  outright (only PSS-signed non-leaf links worked), which
  `chain.zig`'s doc comment recorded as a known limitation. Such a chain now
  verifies. Hostname matching for these leaves runs against the certificate's
  real `subjectAltName`/`commonName` through this module's own walk, so it is
  neither skipped nor weakened — `expected_host` is honoured on every path.

- **2026-08-22** — `extensions.ExtensionEntry` gained `value_slice`, the
  `extnValue` content as offsets rather than bytes. Additive; existing
  callers are unaffected. Needed because `std.crypto.Certificate.Parsed`
  stores slices into the certificate, not pointers.

- **2026-07-28** — New `x509.spkiOf(certificate_der)` → `x509.Spki` — a certificate's
  `SubjectPublicKeyInfo` (full TLV + algorithm OID + parameters + key
  bits) extracted over the defensive `safe.zig` walk, never through
  `std.crypto.Certificate.parse`. Every returned slice borrows the
  caller's buffer. Works on RSASSA-PSS-signed certificates, which std
  cannot parse at all. Adds `safe.oid_*` OID constants.
- **2026-07-19** — Security audit: fixed a memory-safety finding rated CRIT/HIGH (part of
  the collection-wide audit; the root changelog records no further detail
  than this).

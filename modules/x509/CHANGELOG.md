# x509 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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

# x509 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-28** — New `x509.spkiOf(certificate_der)` → `x509.Spki` — a certificate's
  `SubjectPublicKeyInfo` (full TLV + algorithm OID + parameters + key
  bits) extracted over the defensive `safe.zig` walk, never through
  `std.crypto.Certificate.parse`. Every returned slice borrows the
  caller's buffer. Works on RSASSA-PSS-signed certificates, which std
  cannot parse at all. Adds `safe.oid_*` OID constants.
- **2026-07-19** — Security audit: fixed a memory-safety finding rated CRIT/HIGH (part of
  the collection-wide audit; the root changelog records no further detail
  than this).

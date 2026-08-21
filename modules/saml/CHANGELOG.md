# saml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — Re-exported `VerifyKey`. It is the type of `Config.idp_key`, a field on
  this module's own public config, but `xmldsig` was imported privately here, so a consumer
  had to take a direct dependency on `xmldsig` just to name the value it hands to `saml`.
  Additive. Found by writing `example/main.zig` — the first code to configure this module
  from outside.

- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: against real
  `xmlsec1`-produced XML-Encryption and OpenSSL-signed fixtures.
- **2026-07-28** — Holder-of-Key subject confirmation now performs **cross-form** matching
  (an `<ds:X509Certificate>` confirmation against a configured bare
  `presented_holder_key`, and a `<ds:KeyValue>` confirmation against a
  configured `presented_holder_cert_der`) over `x509.spkiOf`, comparing
  key parameters — RSA modulus/exponent, P-256 affine point — never
  encodings. **BREAKING (behavioral, not signature):** pairings that
  previously always returned `error.HolderOfKeyCrossFormUnsupported` can
  now confirm a subject, and that error's meaning narrows to "key
  material was named but none of it could be reduced to a comparable
  key". Same-form matching, and every non-HoK path, are unchanged. New
  sibling dependency: `x509`.

# saml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- Holder-of-Key subject confirmation now performs **cross-form** matching
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

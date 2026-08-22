# webauthn — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — `parseCredentialKey` explicitly refuses the AKP key type
  (RFC 9964 `kty` 7, which carries ML-DSA) with `error.UnsupportedKty`.
  WebAuthn has not registered ML-DSA — draft-vitap-ml-dsa-webauthn is still a
  draft with no COSE algorithm assigned for WebAuthn use — so accepting one
  would claim a verification path that does not exist. Prompted by `cbor`
  gaining AKP support; caught by `check-pubfn-reach`, not by this module's own
  tests, because nothing in them reaches that switch.
- **2026-08-06** — Security audit: `verifyAttestation` passed an attacker-supplied
  certificate straight to std's DER parser, which aborts the process on malformed input;
  fixed by routing through this collection's own defensive x509 parser, along with 6
  further findings.
- **2026-07-21** — New module: WebAuthn / FIDO2 Relying-Party VERIFIER (W3C WebAuthn
  Level 3).

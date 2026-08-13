# webauthn — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: `verifyAttestation` passed an attacker-supplied
  certificate straight to std's DER parser, which aborts the process on malformed input;
  fixed by routing through this collection's own defensive x509 parser, along with 6
  further findings.
- **2026-07-21** — New module: WebAuthn / FIDO2 Relying-Party VERIFIER (W3C WebAuthn
  Level 3).

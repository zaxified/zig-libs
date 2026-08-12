# hpke — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- `mode_psk`, `mode_auth` and `mode_auth_psk` are now anchored to RFC
  9180's own Appendix A vectors (A.1.2/3/4 for X25519, A.3.2/3/4 for
  P-256) instead of only to this module's round-trip; the implementations
  needed no correction. New single-shot wrappers `sealPsk`/`openPsk`,
  `sealAuth`/`openAuth`, `sealAuthPsk`/`openAuthPsk` alongside the
  existing `sealBase`/`openBase`. **BREAKING (behavioral):** a
  psk-bearing mode now rejects a PSK shorter than `Nh` with
  `error.PskTooShort` — deliberately stricter than the RFC's
  `VerifyPSKInputs` pseudocode, on the grounds that §5.1.2's "MUST have
  at least 32 bytes of entropy" cannot hold for a PSK shorter than 32
  bytes, and length is the only checkable projection of that
  requirement. Appendix A's own PSK vectors satisfy the floor.

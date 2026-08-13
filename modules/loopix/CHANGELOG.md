# loopix — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on Loopix (Piotrowska et al.,
  USENIX Sec 2017) / Nym — no interop KAT exists for the anonymity metric (design
  reference, not a test anchor).
- **2026-07-17** — New module: Loopix mixnet (Piotrowska et al., USENIX Security 2017 —
  Nym's design) — Poisson mix + cover traffic over Sphinx, model-checked in netsim
  against a global-passive-adversary anonymity invariant.

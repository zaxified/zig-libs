# drand — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: `verifyRound` accepted a malleated beacon signature
  (a missing subgroup check on the signature itself), which could let two honest
  verifiers derive different "verified" randomness for the same round; fixed, along with
  two further findings.
- **2026-07-24** — New module: drand randomness-beacon client core — chain-info + round
  codec + BLS-verify a round signature against the chain public key (`bls12_381`,
  quicknet/unchained-G1 ciphersuite reused from `tlock`).

# threshold_ecdsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- The GG18 Appendix-A Fiat-Shamir transcripts now bind the Paillier
  **generator** `Γ`, not only the modulus `N` (audit F3 — an unbound
  public value in the verification equation is a value a prover can
  still vary after the challenge is fixed). A companion fail-closed
  check, `root.paillierGeneratorIsStandard`, rejects any received
  Paillier key whose `Γ != N+1` at every prove and verify entry point,
  alongside the existing F1/F2 gates. **BREAKING (wire):** absorbing a
  new value changes every challenge, so proofs minted before this change
  do not verify after it; the three Fiat-Shamir domain tags were bumped
  `…/v1` → `…/v2` so the break surfaces as a plain verification failure.
  No interop is affected — these proofs were never byte-compatible with
  any other implementation.

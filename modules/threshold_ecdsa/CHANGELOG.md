# threshold_ecdsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-29** — The GG18 Appendix-A Fiat-Shamir transcripts now bind the Paillier
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
- **2026-07-28** — Fuzz harnesses over the three length-prefixed deserializers —
  `FeldmanCommitments.fromBytesAlloc`, `PublicKeys.fromBytesAlloc` and
  `AuxParams.fromBytesAlloc` — which had none, under the collection's "never panic and
  never over-allocate on arbitrary input" threat model. Tests only.
- **2026-07-21** — Security audit: `signWithShares` now `secureZero`s its `Ephemeral[]`
  scratch — every party's ephemeral nonce `k`, blinding `gamma`, weighted key share `w`,
  `delta` and `sigma` — before returning it to the allocator, instead of leaving that
  residue in freed heap. The ZK proofs' internal masks were already zeroed; this driver
  array was the one gap.
- **2026-07-18** — The ZK proofs' modular-exponentiation path was rewired onto `montint`:
  about **2.8× faster signing**, and it closed the audit's performance finding — the
  Paillier/ZK hot path had measured ~7–8× slower than an OpenSSL-class bignum on
  `std.crypto.ff`'s schoolbook Montgomery multiply, and after the rewire the 4096-bit
  modexp measures ~1.78×, below the finding bar. No API change.
- **2026-07-16** — Πprm/Πmod proofs of correct generation for the ring-Pedersen auxiliary
  parameters, so a receiver can check that a peer's aux params were honestly generated and
  not merely well-shaped. Closes the audit finding the structural validation below opened;
  the proofs are an out-of-band setup artifact, not auto-exchanged in the online flow, so
  the always-on floor is still what guards the signing path.
- **2026-07-15** — **BEHAVIOURAL, not breaking** — received ring-Pedersen auxiliary
  parameters are now validated, and a key-size floor is enforced, at **every** prove and
  verify entry point: `Ñ` must be composite, `1 < h1, h2 < Ñ`, the Jacobi symbol `(h/Ñ)`
  must be `+1`, and both `Ñ` and the Paillier `N` must exceed `q⁷` (≈2¹⁷⁹²). Without the
  floor the `t1 ≤ q⁷` / `s1 ≤ q³` range bounds inside the proofs were vacuous. Aux params
  and keys that previously went through are now rejected fail-closed with
  `error.InvalidAuxParams`. This is the first pair of findings from the module's Fable-tier
  security audit, which raised **six findings, all fixed** — these two, the perf rewire,
  the `Ephemeral[]` zeroization, the Paillier-generator transcript binding, and the
  variable-time Paillier `L`-function division, which was closed in the `paillier` module
  where the division actually lives (documented as accepted, since the value it divides is
  masked by a fresh uniform `β'` and is therefore independent of the secret nonce). A
  seventh — that the security-critical ZK reject tests were skipped in the default build —
  was **withdrawn**: measured rather than read, this module is `heavy`, so the default lane
  compiles it at ReleaseSafe and runs all fifteen of them.

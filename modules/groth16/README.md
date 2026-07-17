# groth16

A **Groth16 zk-SNARK prover** over the BN254 (alt-bn128) curve — the
counterpart to the sibling [`bn254`](../bn254/) module's Groth16 *verifier*
(`bn254.groth16Verify`). Given a rank-1 constraint system (R1CS), a proving key
(the circuit's CRS), and a satisfying witness, the prover produces the
3-element proof `(πA ∈ G1, πB ∈ G2, πC ∈ G1)` that the `bn254` verifier
accepts. Construction: Groth 2016, *"On the Size of Pairing-based
Non-interactive Arguments."*

**Status: Phase-1 scaffold.** The entire mechanical + math layer is
implemented and heavily anchored; the *prover core* (`setup` + `prove`) is
gated behind `gate.prover_core_implemented` (`false`) and `@panic`s until
implemented — an **Opus** task, because the `bn254` verifier is a complete
deterministic anchor (see [SPEC.md](SPEC.md)).

## What is real today

| File | Role |
|---|---|
| `field.zig` | `Fr` helpers over `bn254`'s scalar field (`frFromU64`, `frPowU64`) |
| `poly.zig` | dense `Fr[x]` arithmetic + division by the vanishing polynomial `Z(x)=x^n−1` |
| `domain.zig` | radix-2 evaluation domain — `n`-th roots of unity `ω=5^{(r−1)/n}`, `Z` |
| `fft.zig` | radix-2 NTT / inverse-NTT over `Fr` + FFT polynomial multiplication |
| `msm.zig` | naive multi-scalar multiplication in `G1`/`G2` |
| `r1cs.zig` | rank-1 constraint system + witness satisfaction |
| `qap.zig` | R1CS→QAP interpolation + the `A·B−C` divisibility oracle |
| `prover.zig` | **gated** `setup`/`prove`; **real** `brokenProof` positive control |

## The anchor

Correctness is anchored by the sibling `bn254` module's Groth16 verifier:
`prove(setup(…)) → bn254.groth16Verify == true`, and any tampered proof/public
input → `false`. That end-to-end test is gated (needs the core). Today's teeth
come from the sub-anchors that run without the core:

- **NTT round-trip:** `intt(ntt(v)) == v`.
- **FFT vs schoolbook:** `fft.mulViaFFT == poly.mulSchoolbook`.
- **MSM vs naive:** single-term / linearity checks against `G.scalarMul`.
- **QAP divisibility == R1CS satisfaction:** `qap.checkDivisible` and
  `r1cs.System.isSatisfied` must agree on every witness — this proves the
  interpolation/vanishing-division stack.
- **Positive control:** `bn254.groth16Verify` *rejects* `prover.brokenProof()`
  (a deliberately-wrong "proof"), proving the anchor has teeth before `prove`
  exists.

## Using it

```zig
const groth16 = @import("groth16");

// Build a tiny circuit: prove x·x = out.
const cons = groth16.r1cs.example.constraints();
const sys = groth16.r1cs.example.system(&cons);
const witness = groth16.r1cs.example.goodWitness(); // [1, 5, 25]

// The QAP divisibility oracle (real today): true iff witness satisfies R1CS.
_ = groth16.qap.checkDivisible(2, sys, &witness); // true

// Proving (gated until the Opus core lands):
//   const kp = groth16.setup(2, sys, toxic_tau);
//   const pf = groth16.prove(2, kp.pk, sys, &witness, .{ .r = r, .s = s });
//   try std.testing.expect(try @import("bn254").groth16Verify(kp.vk, pf, witness[1..2]));
```

## Verify

```
zig build test-groth16                       # Debug: 26 pass, 2 skip (gated core)
zig build test-groth16 -Doptimize=ReleaseFast
zig fmt --check modules/groth16
```

Provenance: pure clean-room-from-spec (Groth 2016) — no third-party source
ported. See [SPEC.md](SPEC.md) for the design, the Fable-vs-Opus tier call, and
the anchor plan. Depends on the sibling `bn254` module for `Fr`/`G1`/`G2`/the
pairing/the verifier.

# groth16

A **Groth16 zk-SNARK prover** over the BN254 (alt-bn128) curve — the
counterpart to the sibling [`bn254`](../bn254/) module's Groth16 *verifier*
(`bn254.groth16Verify`). Given a rank-1 constraint system (R1CS), a proving key
(the circuit's CRS), and a satisfying witness, the prover produces the
3-element proof `(πA ∈ G1, πB ∈ G2, πC ∈ G1)` that the `bn254` verifier
accepts. Construction: Groth 2016, *"On the Size of Pairing-based
Non-interactive Arguments."*

**Status: implemented.** The entire mechanical + math layer AND the prover
core (`setup` + `prove`) are implemented and anchored. `gate.
prover_core_implemented` is `true`; the flag is retained as a self-documenting
marker of the scaffold→core boundary, not a live switch — `setup`/`prove` no
longer `@panic`. The core was an **Opus** task, not a Fable one, because the
`bn254` verifier is a complete deterministic anchor (see [SPEC.md](SPEC.md)).

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
| `prover.zig` | **real** `setup`/`prove` (the toy CRS + proof assembly) + `brokenProof` positive control |

## The anchor

Correctness is anchored by the sibling `bn254` module's Groth16 verifier:
`prove(setup(…)) → bn254.groth16Verify == true`, and any tampered proof/public
input → `false`. That end-to-end test now runs (the core is implemented).
Today's teeth come from the sub-anchors that run independently, plus the
end-to-end test itself:

- **NTT round-trip:** `intt(ntt(v)) == v`.
- **FFT vs schoolbook:** `fft.mulViaFFT == poly.mulSchoolbook`.
- **MSM vs naive:** single-term / linearity checks against `G.scalarMul`.
- **QAP divisibility == R1CS satisfaction:** `qap.checkDivisible` and
  `r1cs.System.isSatisfied` must agree on every witness — this proves the
  interpolation/vanishing-division stack.
- **Positive control:** `bn254.groth16Verify` *rejects* `prover.brokenProof()`
  (a deliberately-wrong "proof"), proving the anchor has teeth independent of
  a real `prove` call.
- **End-to-end:** `prove(setup(…)) → bn254.groth16Verify == true`, plus
  tamper/wrong-public-input/non-satisfying-witness cases → `false`
  (`harness_test.zig`).

## Using it

```zig
const groth16 = @import("groth16");

// Build a tiny circuit: prove x·x = out.
const cons = groth16.r1cs.example.constraints();
const sys = groth16.r1cs.example.system(&cons);
const witness = groth16.r1cs.example.goodWitness(); // [1, 5, 25]

// The QAP divisibility oracle (real today): true iff witness satisfies R1CS.
_ = groth16.qap.checkDivisible(2, sys, &witness); // true

// Proving:
const toxic_waste = groth16.ToxicWaste{ .tau = tau, .alpha = alpha, .beta = beta, .gamma = gamma, .delta = delta };
const kp = try groth16.setup(2, allocator, sys, 1, toxic_waste);
defer groth16.freeKeyPair(allocator, kp);
const pf = groth16.prove(2, kp.pk, sys, 1, &witness, .{ .r = r, .s = s });
try std.testing.expect(try @import("bn254").groth16Verify(kp.vk, pf, witness[1..2]));
```

**Toxic waste:** `setup`'s `ToxicWaste{tau, alpha, beta, gamma, delta}` is the
INSECURE, test-only trusted-setup material — see `ToxicWaste`'s doc comment
in `prover.zig`. A real deployment sources the CRS from a distributed MPC
ceremony instead of materialising these five scalars directly. `ToxicWaste`
carries a `deinit()` that zeroes all five fields; `setup` also wipes its own
internal copy on every exit.

## Verify

```
zig build test-groth16                       # Debug: all tests pass, none gated
zig build test-groth16 -Doptimize=ReleaseFast
zig fmt --check modules/groth16
```

Provenance: pure clean-room-from-spec (Groth 2016) — no third-party source
ported. See [SPEC.md](SPEC.md) for the design, the Fable-vs-Opus tier call, and
the anchor plan. Depends on the sibling `bn254` module for `Fr`/`G1`/`G2`/the
pairing/the verifier.

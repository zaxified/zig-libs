# groth16

A **Groth16 zk-SNARK prover** over the BN254 (alt-bn128) curve — the
counterpart to the sibling [`bn254`](../bn254/) module's Groth16 *verifier*
(`bn254.groth16Verify`). Given a rank-1 constraint system (R1CS), a proving key
(the circuit's CRS), and a satisfying witness, the prover produces the
3-element proof `(πA ∈ G1, πB ∈ G2, πC ∈ G1)` that the `bn254` verifier
accepts. Construction: Groth 2016, *"On the Size of Pairing-based
Non-interactive Arguments."*

The prover core (`setup` + `prove`, over a hand-built R1CS and a toy CRS) and the snarkjs ecosystem layer
(`.zkey`/`.wtns`/`.r1cs`/`.ptau` readers, the zkey prover, phase-2 setup/contribute/verify) are implemented and
anchored by the `bn254` verifier and by real `snarkjs`/`circom` files (see [SPEC.md](SPEC.md)).

## What is real today

| File | Role |
|---|---|
| `field.zig` | `Fr` helpers over `bn254`'s scalar field (`frFromU64`, `frPowU64`) |
| `poly.zig` | dense `Fr[x]` arithmetic + division by the vanishing polynomial `Z(x)=x^n−1` |
| `domain.zig` | radix-2 evaluation domain — `n`-th roots of unity `ω=5^{(r−1)/n}`, `Z` |
| `fft.zig` | radix-2 NTT / inverse-NTT over `Fr` + FFT polynomial multiplication |
| `msm.zig` | multi-scalar multiplication in `G1`/`G2`: naive (constant-time, the toy prover) and Pippenger (variable-time, `zkprove`) |
| `r1cs.zig` | rank-1 constraint system + witness satisfaction |
| `qap.zig` | R1CS→QAP interpolation + the `A·B−C` divisibility oracle |
| `prover.zig` | **real** `setup`/`prove` (the toy CRS + proof assembly) + `brokenProof` positive control |
| `snarkjs_export.zig` | renders our `Proof`/`VerifyingKey`/public inputs into the exact JSON shape `snarkjs` parses — closes the one blind spot the `bn254`-verifier anchor can't see (it decodes our own encoding; see `SPEC.md` §5a) |
| `snarkjs_import.zig` | the reverse: `parseProof`/`parseVerifyingKey`/`parsePublic` read snarkjs's `proof.json`/`verification_key.json`/`public.json` (canonical decimals, on-curve, `G2` in the subgroup; anything else is an error) |
| `snarkjs_bin.zig` | the iden3 binary container and the field/point encodings inside it |
| `zkey.zig` | snarkjs `.zkey` (Groth16 proving key) reader and writer — round-trips snarkjs's files byte for byte |
| `circom.zig` | circom `.r1cs` reader, `.wtns` reader and writer |
| `ptau.zig` | snarkjs powers-of-tau (`.ptau`) reader, points decoded on demand; `readCut(gpa, io, file, power)` reads by position only what a smaller power needs (a ceremony file too large for memory) |
| `zkprove.zig` | **the real prover**: `.zkey` + witness → proof, quotient on a coset; Pippenger MSM (variable-time in the witness, the default) or `proveWith(…, .{ .msm = .constant_time })` (~21× slower) |
| `phase2.zig` | phase-2 ceremony: `newZkey(r1cs, ptau)`, `contribute`, `verifyContribution`, `verify` |
| `hash_to_g2.zig` | `hashToG2(msg, dst)`: RFC 9380 hash to BN254's G2 with the SVDW map (gnark-crypto's `HashToG2`, its vectors reproduced); `phase2.hashToG2` uses it for a contribution record's `g2_sp` |
| `solidity.zig` | `verifier(vk, name)`: a Solidity verifier contract for a key (snarkjs's `verifyProof` signature, EVM precompiles 0x06–0x08); the matching calldata is `snarkjs_export.solidityCalldata(proof, public)` |

## The anchor

Correctness is anchored by the sibling `bn254` module's Groth16 verifier:
`prove(setup(…)) → bn254.groth16Verify == true`, and any tampered proof/public
input → `false`. The anchor is that end-to-end test plus the sub-anchors that
run independently of it:

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
- **Foreign-verifier cross-check (encoding, not just algebra):** a real
  `snarkjs@0.7.6` (fetched via `bunx`, run OUTSIDE the test suite) accepts a
  proof from this module's own `setup`/`prove`, exported through
  `snarkjs_export.zig`, and rejects a one-limb-tampered copy. Frozen as
  literals, with the exact commands/output, in `snarkjs_kat_test.zig` — see
  `SPEC.md` §5a for why this closes a gap the sibling `bn254` verifier alone
  could not.

## Proving a circom circuit

```zig
const groth16 = @import("groth16");

// Files from circom + snarkjs (read them however you like; the readers take bytes).
var z = try groth16.zkey.parse(gpa, zkey_bytes); // snarkjs `.zkey`
defer z.deinit(gpa);
const w = try groth16.circom.parseWitness(gpa, wtns_bytes); // circom `.wtns`
defer groth16.circom.freeWitness(gpa, w); // wipes, then frees

// Fresh r, s for EVERY proof. Secrets go in by pointer; the caller wipes them.
var rand: groth16.Randomizers = undefined;
groth16.Randomizers.randomInto(&rand, io); // draws straight into `rand`, no copy in this frame
defer std.crypto.secureZero(u8, std.mem.asBytes(&rand));
const proof = try groth16.zkprove.prove(gpa, z, w, &rand);
std.debug.assert(try groth16.verify(z.verifyingKey(), proof, w[1 .. z.n_public + 1]));
const json = try groth16.snarkjs_export.proofJson(gpa, proof); // what `snarkjs groth16 verify` reads
```

Before trusting a key someone else made, check it against the circuit and the
ceremony it claims to come from:

```zig
var r = try groth16.circom.parseR1cs(gpa, r1cs_bytes);
const p = try groth16.ptau.Ptau.parse(ptau_bytes);
switch (try groth16.phase2.verify(gpa, io, r, p, z)) {
    .ok => {},
    else => |why| return error.UntrustedKey, // circuit_mismatch, bad_delta, …
}
```

Making a key yourself: `phase2.newZkey(gpa, r, p)`, then one
`phase2.contribute(gpa, &z, &x, &s, "name")` per participant with fresh secrets
they destroy afterwards. `tools/snarkjs/g16.zig` is all of this as a command
line. ⚠ snarkjs's own `zkey verify` rejects keys made or contributed here
(SPEC.md § 4b); its prover and verifier accept them.

## Using it (hand-built R1CS, toy setup)

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
const kp = try groth16.setup(2, allocator, sys, 1, &toxic_waste);
defer groth16.freeKeyPair(allocator, kp);
const pf = try groth16.prove(2, kp.pk, sys, 1, &witness, &.{ .r = r, .s = s });
try std.testing.expect(try @import("bn254").groth16Verify(kp.vk, pf, witness[1..2]));
```

**Toxic waste:** `setup`'s `ToxicWaste{tau, alpha, beta, gamma, delta}` is the
INSECURE, test-only trusted-setup material — see `ToxicWaste`'s doc comment
in `prover.zig`. A real deployment sources the CRS from a distributed MPC
ceremony instead of materialising these five scalars directly. `ToxicWaste`
carries a `deinit()` that zeroes all five fields; `setup` also wipes its own
internal copy on every exit.

## Limits

- **Proofs are malleable** (Groth16 itself): never use proof bytes as a nullifier or replay key.
- **`verify` trusts the verifying key.** It validates the proof (on-curve, G2 subgroup), not the key; a key from a
  `.zkey` is only as trustworthy as whoever made it (`phase2.verify` checks it against the circuit and the `.ptau`).
- **`zkprove.prove` is variable-time in the witness** (Pippenger MSM); `proveWith(…, .{ .msm = .constant_time })` is
  the constant-time choice, about 21× slower.
- **`setup` is a toy**: the toxic waste is in memory. Real keys come from a ceremony (`phase2`).
- `zkprove` refuses a `2^28` domain (`DomainTooLarge`); files are read from memory, not streamed.

SPEC.md § 5b has the reasons and the residual risks.

## Not provided

No multi-threading, witness calculation, circuit DSL, PLONK or other curves, and
snarkjs's own `zkey verify` rejects keys made or contributed here. What is deliberately refused is in SPEC.md *What is
deliberately not done*; what is wanted and open is in *Backlog / deferred* and *Roadmap*.

## Verify

```
scripts/modtest groth16
scripts/modtest groth16 -Doptimize=ReleaseFast   # also runs the stack-probe and heap-wipe tests
zig fmt --check modules/groth16
```

Provenance: pure clean-room-from-spec (Groth 2016) — no third-party source
ported. The test data in `src/testdata/snarkjs/` is output of circom 2.2.3 and
snarkjs@0.7.6 run as black-box oracles by `tools/snarkjs/gen.sh` (their GPL
source was not read; the files hold points and field elements of our own
circuit, see SPEC.md § 8). `hash_to_g2.zig` follows RFC 9380 with gnark-crypto (Apache-2.0) as the design reference
for its cofactor clearing; its vectors are gnark-crypto's (SPEC.md § 8). See [SPEC.md](SPEC.md) for the design, the Fable-vs-Opus tier call, and
the anchor plan. Depends on the sibling `bn254` module for `Fr`/`G1`/`G2`/the
pairing/the verifier.

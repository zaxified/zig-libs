# voprf

RFC 9497 Oblivious Pseudorandom Functions — **ristretto255-SHA512**
ciphersuite. All three modes: base **OPRF**, verifiable **VOPRF**
(batched DLEQ proof), and partially-oblivious **POPRF** (public `info`
input). Pure std (`std.crypto.ecc.Ristretto255` + SHA-512), no
allocation, no internal RNG (blind/proof randomness is caller-supplied;
see `scalarFromWideBytes`).

KAT-validated byte-exact against RFC 9497 Appendix A.1 (all modes,
including batch-size-2 proofs) and RFC 9380 Appendix K.3.

```zig
const voprf = @import("voprf");

// Server setup (offline)
const kp = try voprf.deriveKeyPair(.voprf, seed, "key info");

// Client: blind (blind_scalar = scalarFromWideBytes(64 CSPRNG bytes))
const blinded = try voprf.blind(.voprf, input, blind_scalar);

// Server: evaluate + DLEQ proof (proof_r = fresh random scalar)
const eval = try voprf.blindEvaluateVerifiable(kp.sk, kp.pk, blinded, proof_r);

// Client: verify proof (fail closed), unblind, hash
const output = try voprf.finalizeVerifiable(
    input, blind_scalar, eval.evaluated_element, blinded, kp.pk, eval.proof);
```

See `SPEC.md` for the threat model and the DLEQ transcript details.

Provenance: clean-room from RFC 9497, a public IRTF specification, with its own
test vectors as the byte-exact anchor. No reference implementation consulted.
Detail in this module's own [`NOTICE`](NOTICE); it carries no condition beyond
zig-libs' MIT license.

Test: `zig build test-voprf`

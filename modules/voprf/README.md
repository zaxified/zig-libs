# voprf

RFC 9497 Oblivious Pseudorandom Functions — **all five ciphersuites**
(ristretto255-SHA512 at the top level; `Decaf448Shake256`, `P256Sha256`,
`P384Sha384`, `P521Sha512`, or `Suite(.p256_sha256)`, with the same function
names). All three modes: base **OPRF**, verifiable **VOPRF** (batched DLEQ
proof), and partially-oblivious **POPRF** (public `info` input), as functions
and as per-role client/server objects. Groups from std `Ristretto255` (secret
mults via `ct25519`) and the siblings `decaf448`, `p256`, `p384`, `p521`; RFC
9380 hash-to-curve for the NIST curves in `src/h2c.zig`. No allocation, no
internal RNG (blind/proof randomness is caller-supplied; see
`scalarFromWideBytes`).

KAT-validated byte-exact against every RFC 9497 Appendix A vector (A.1-A.5,
all modes, including batch-size-2 proofs) and RFC 9380 Appendix J.1.1/J.2.1/
J.3.1 and K.1/K.3.

```zig
const voprf = @import("voprf");

// Server setup (offline). Secrets go in by pointer, out through `out`.
var kp: voprf.KeyPair = undefined;
try voprf.deriveKeyPair(.voprf, &seed, "key info", &kp);

// Client: blind (voprf.scalarFromWideBytes(&wide_64_csprng_bytes, &blind_scalar))
const blinded = try voprf.blind(.voprf, input, &blind_scalar);

// Server: evaluate + DLEQ proof (proof_r = fresh random scalar)
const eval = try voprf.blindEvaluateVerifiable(&kp.sk, kp.pk, blinded, &proof_r);

// Client: verify proof (fail closed), unblind, hash
var output: [voprf.Nh]u8 = undefined;
try voprf.finalizeVerifiable(
    input, &blind_scalar, eval.evaluated_element, blinded, kp.pk, eval.proof, &output);
```

The same flow on P-256, with the context objects:

```zig
const S = voprf.P256Sha256;
var server = try S.VoprfServer.derive(&seed, "key info");
defer server.wipe();
var client = try S.VoprfClient.blind(input, &blind_scalar); // S.Ns-byte scalar
defer client.wipe();
const ev = try server.blindEvaluate(client.blinded_element, &proof_r);
var out: [S.Nh]u8 = undefined;
try client.finalize(input, ev.evaluated_element, ev.proof, server.publicKey(), &out);
```

Every secret-handling entry point burns the stack it used before it returns
(`SPEC.md` § Secret residue on the dead stack).

See `SPEC.md` for the threat model and the DLEQ transcript details.

Provenance: clean-room from RFC 9497, a public IRTF specification, with its own
test vectors as the byte-exact anchor. No reference implementation consulted.
Detail in this module's own [`NOTICE`](NOTICE); it carries no condition beyond
zig-libs' MIT license.

Test: `zig build test-voprf`

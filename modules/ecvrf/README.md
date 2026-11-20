# ecvrf

ECVRF-EDWARDS25519-SHA512-TAI, the elliptic-curve Verifiable Random
Function (VRF) ciphersuite from RFC 9381 ("Verifiable Random Functions
(VRFs)", IRTF CFRG, August 2023), built on
`std.crypto.ecc.Edwards25519`, `std.crypto.hash.sha2.Sha512` and the sibling
`ct25519` module (constant-time secret-scalar multiplication).

A VRF is the public-key analogue of a keyed cryptographic hash: only the
holder of the secret key can compute a proof `pi` for an input
`alpha_string`, but anyone with the public key can verify `pi` and — only
on success — recover the deterministic pseudorandom output `beta_string`.
The value is unpredictable before proving and cannot be biased by the
prover (a valid `pi` for a given `(pk, alpha)` is unique), which is why
VRFs show up in:

- **Blockchain leader election / committee selection** — the value each
  round's leader/committee is drawn from must be unpredictable in advance
  (so nobody can grind for a favorable outcome) yet publicly verifiable
  after the fact (so nobody can claim a false result). Algorand's
  sortition is the RFC's own headline example.
- **DNSSEC NSEC5** — VRF-based authenticated denial of existence that,
  unlike plain NSEC/NSEC3 hashing, resists offline zone enumeration
  (an attacker cannot precompute the hash of every possible name without
  the zone operator's secret key).

`prove`/`proofToHash`/`verify` and every RFC 9381 §5.4 auxiliary function
are checked byte-exact against RFC 9381 Appendix B.3's three official test
vectors, including every published intermediate value. See
[SPEC.md](SPEC.md) for design notes, [NOTICE](NOTICE) for provenance.

| File | Contents |
|---|---|
| `root.zig` | the public surface (flat re-exports of `ecvrf.zig`), `meta`, and the test aggregator |
| `ecvrf.zig` | `prove`/`proofToHash`/`verify`, `KeyPair`, key derivation, and the §5.4 auxiliary functions (`encodeToCurve`, `nonceGeneration`, `challengeGeneration`, `decodeProof`, `validateKey`, `stringToPoint`) |
| `burn.zig` | zeroes the dead stack under the secret-scalar entry points |
| `kat_vectors.zig` | RFC 9381 Appendix B.3's three official ECVRF-EDWARDS25519-SHA512-TAI test vectors (Examples 16, 17, 18) |
| `kat_test.zig` | Byte-exact KAT assertions against `kat_vectors.zig`, plus tamper/negative tests the RFC does not itself publish |
| `fuzz_test.zig` | shared plumbing of the deterministic fuzz driver (`ECVRF_FUZZ`); the harness bodies are in `ecvrf.zig` |
| `stackprobe_test.zig`, `stackprobe2_test.zig` | dead-stack residue probes (optimized builds) |
| `ctgrind_harness.zig` | constant-time evidence, run by `scripts/checks/ctgrind.sh ecvrf`, not part of the tests |

## Import

```zig
const ecvrf = @import("ecvrf");
```

## Usage

```zig
// Key generation: SK is a 32-byte seed (any 32 random bytes — same
// shape as an Ed25519 seed, RFC 8032 §5.1.5).
var sk: ecvrf.SecretKey = undefined;
io.random(&sk);
const pk = ecvrf.publicKey(&sk);

// Prove: only the secret-key holder can do this.
const alpha = "some public input";
const pi = ecvrf.prove(&sk, alpha); // 80-byte proof

// Anyone can independently derive beta from pi alone (no pk/alpha
// needed — this is just "does pi decode", not "is pi valid for this
// input"; see verify below for the check that matters to a relying
// party).
const beta_from_pi = try ecvrf.proofToHash(pi); // 64-byte VRF output

// Verify: anyone with pk can check pi against (alpha) and recover the
// SAME beta only if pi is genuinely valid for (pk, alpha).
const beta = try ecvrf.verify(pk, alpha, pi); // error.InvalidProof / error.InvalidPublicKey on failure

// Many proofs under one key: derive the public key once (the same
// bytes, without the `Y = x*B` multiplication `prove` repeats). Build it
// only with fromSecretKey; it holds the seed, so wipe it when done.
var kp: ecvrf.KeyPair = undefined;
ecvrf.KeyPair.fromSecretKey(&kp, &sk);
const pi2 = kp.prove(alpha);
```

Public keys and `Gamma` are decoded strictly per RFC 8032 §5.1.3: a
non-canonical encoding (`y >= p`, or a sign bit on a point with `x = 0`) is
refused, so neither a key nor a proof has a second valid 32-byte spelling.

`verify` fails closed: every malformed input (bad public key encoding, a
low-order public key, a structurally invalid or tampered proof, a
mismatched challenge) returns `error.InvalidPublicKey` or
`error.InvalidProof` — never a panic on attacker-controlled input.

## Ciphersuite

Only **ECVRF-EDWARDS25519-SHA512-TAI** (RFC 9381 §5.5, `suite_string =
0x03`) is implemented. `0x04` is the sibling ELL2 suite (same curve and
hash, RFC 9380 Elligator2 instead of try-and-increment) and is easy to
conflate with it; the two are not interchangeable.

## Not provided

The other ciphersuites of RFC 9381: **ECVRF-P256-SHA256-TAI / -SSWU**
(NIST P-256) and **ECVRF-EDWARDS25519-SHA512-ELL2** are open work (SPEC
*Backlog / deferred*); the non-elliptic-curve **RSA-FDH-VRF** family
(Appendix A) and batch verification are refused (SPEC *What is
deliberately not done*).

## Import graph

```
ecvrf → ct25519 (constant-time mul / mulBase for secret scalars)
      → std.crypto.ecc.Edwards25519 (+ its scalar submodule)
      → std.crypto.hash.sha2.Sha512
```

One sibling zig-libs module dependency (`ct25519`); otherwise pure `std`.

## Verify

```
scripts/modtest ecvrf        # the module's tests
```

`kat_test.zig` asserts byte-exact output against RFC 9381 Appendix B.3's
three official ECVRF-EDWARDS25519-SHA512-TAI vectors — secret-key-to-scalar
and secret-key-to-public-key derivation, `encodeToCurve`'s `H` (including
the published `try_and_increment` counter, independently cross-checked),
the nonce (`k_string` pre- and `k` post-reduction), the full 80-byte
`prove` output, and the 64-byte `proofToHash`/`verify` output — plus
negative tests the RFC does not itself publish: tampering each of `pi`'s
three fields (`Gamma`/`c`/`s`) independently, a wrong `alpha`, and
small-order/non-canonical public keys, all rejected cleanly rather than
crashing. Fuzz: `ECVRF_FUZZ=<runs>`. SPEC *Verification* has the rest.

Provenance: see [NOTICE](NOTICE).

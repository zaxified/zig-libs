# ecvrf

ECVRF-EDWARDS25519-SHA512-TAI, the elliptic-curve Verifiable Random
Function (VRF) ciphersuite from RFC 9381 ("Verifiable Random Functions
(VRFs)", IRTF CFRG, August 2023), built entirely on
`std.crypto.ecc.Edwards25519` and `std.crypto.hash.sha2.Sha512`.

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

**Status: implemented.** `prove`/`proofToHash`/`verify` and every RFC
9381 §5.4 auxiliary function are real; validated byte-exact against RFC
9381 Appendix B.3's three official test vectors, including every
published intermediate value. See [SPEC.md](SPEC.md) for design notes,
[NOTICE](NOTICE) for provenance.

| File | Contents |
|---|---|
| `ecvrf.zig` | `prove`/`proofToHash`/`verify`, key derivation, and the §5.4 auxiliary functions (`encodeToCurve`, `nonceGeneration`, `challengeGeneration`, `decodeProof`, `validateKey`) |
| `kat_vectors.zig` | RFC 9381 Appendix B.3's three official ECVRF-EDWARDS25519-SHA512-TAI test vectors (Examples 16, 17, 18) |
| `kat_test.zig` | Byte-exact KAT assertions against `kat_vectors.zig`, plus tamper/negative tests the RFC does not itself publish |

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
const pk = ecvrf.publicKey(sk);

// Prove: only the secret-key holder can do this.
const alpha = "some public input";
const pi = ecvrf.prove(sk, alpha); // 80-byte proof

// Anyone can independently derive beta from pi alone (no pk/alpha
// needed — this is just "does pi decode", not "is pi valid for this
// input"; see verify below for the check that matters to a relying
// party).
const beta_from_pi = try ecvrf.proofToHash(pi); // 64-byte VRF output

// Verify: anyone with pk can check pi against (alpha) and recover the
// SAME beta only if pi is genuinely valid for (pk, alpha).
const beta = try ecvrf.verify(pk, alpha, pi); // error.InvalidProof / error.InvalidPublicKey on failure
```

`verify` fails closed: every malformed input (bad public key encoding, a
low-order public key, a structurally invalid or tampered proof, a
mismatched challenge) returns `error.InvalidPublicKey` or
`error.InvalidProof` — never a panic on attacker-controlled input.

## Ciphersuite

Only **ECVRF-EDWARDS25519-SHA512-TAI** (RFC 9381 §5.5, `suite_string =
0x03`) is implemented. RFC 9381 defines two other ciphersuites this
module does NOT cover — see [SPEC.md](SPEC.md)'s "Out of scope" for why:
**ECVRF-P256-SHA256-TAI** (NIST P-256), **ECVRF-EDWARDS25519-SHA512-ELL2**
(same curve/hash, but RFC 9380 Elligator2 hash-to-curve instead of
try-and-increment — `suite_string = 0x04`, easy to conflate with this
module's `0x03` since both are edwards25519/SHA-512), and the
non-elliptic-curve **RSA-FDH-VRF** family (RFC 9381 Appendix A).

## Import graph

```
ecvrf → std.crypto.ecc.Edwards25519 (+ its scalar submodule)
      → std.crypto.hash.sha2.Sha512
```

No sibling zig-libs module dependencies; pure `std`.

## Verify

```
zig build test-ecvrf                          # Debug — all green
zig build -Doptimize=ReleaseFast test-ecvrf   # ReleaseFast — all green
zig fmt --check modules/ecvrf/
```

All 20 tests pass in both modes. `kat_test.zig` asserts byte-exact output
against RFC 9381 Appendix B.3's three official ECVRF-EDWARDS25519-SHA512-TAI
vectors — secret-key-to-scalar and secret-key-to-public-key derivation,
`encodeToCurve`'s `H` (including the published `try_and_increment`
counter, independently cross-checked), the nonce (`k_string` pre- and
`k` post-reduction), the full 80-byte `prove` output, and the 64-byte
`proofToHash`/`verify` output — plus negative tests the RFC does not
itself publish: tampering each of `pi`'s three fields (`Gamma`/`c`/`s`)
independently, a wrong `alpha`, and small-order/non-canonical public
keys, all rejected cleanly rather than crashing.

Provenance: see [NOTICE](NOTICE).

# bbs

BBS signatures (draft-irtf-cfrg-bbs-signatures) — pairing-based
multi-message signatures with zero-knowledge **selective disclosure**
proofs: sign a vector of messages under one header with a single,
constant-size signature, then later prove knowledge of that signature
while revealing only a chosen subset of the signed messages, without
revealing the signature itself or the undisclosed messages. This is the
cryptographic basis of anonymous credentials / verifiable credentials.
Builds directly on the finished `bls12_381` module.

**Status: COMPLETE.** The ciphersuite machinery (generators,
`hash_to_scalar`, `messages_to_scalars`, `calculate_domain`, both
random-scalar sources), key generation (`KeyGen`/`SkToPk`), the
`Signature`/`Proof` wire structs + byte codecs, AND the four
cryptographic cores `sign`/`verify`/`proofGen`/`proofVerify` are all
implemented and byte-exact KAT-pinned against `mattrglobal/pairing_crypto`'s
official `bls12_381_sha_256` fixtures (pinned to
draft-irtf-cfrg-bbs-signatures-12 — see [SPEC.md](SPEC.md)).
`gate.core_implemented = true` and the full suite passes
byte-exact in Debug and ReleaseFast, including the selective-disclosure
proof vectors (fed the draft's deterministic mocked RNG) and the
signature/proof tamper-rejection cases.

| File | Contents |
|---|---|
| `root.zig` | Module doc, `meta`, re-exports, dark-tests aggregator |
| `ciphersuite.zig` | **REAL.** `Suite(.sha256 / .shake256)` — both draft-12 ciphersuites' constants (`P1`/DSTs) and `expandMessage`/`hashToScalar`/`createGenerators`/`messagesToScalars`/`calculateDomain`/`calculateRandomScalars`/`mockedRandomScalars` |
| `keys.zig` | **REAL.** `keyGen`/`skToPk`, `SecretKey`/`PublicKey` + byte codecs |
| `bbs.zig` | `Signature`/`Proof` structs + byte codecs (**REAL**); **FABLE CORE:** `sign`/`verify`/`proofGen`/`proofVerify` (implemented) |
| `gate.zig` | The single switch (`core_implemented`) gating the four cores' KAT tests |
| `kat_vectors.zig` | `mattrglobal/pairing_crypto`'s official `bls12_381_sha_256` fixtures, transcribed verbatim |
| `kat_test.zig` | The byte-exact KAT harness |

## Import

```zig
const bbs = @import("bbs");
```

## API

```zig
const sk = try bbs.keyGen(key_material, key_info, null); // KeyGen, draft §3.4.1
const pk = bbs.skToPk(sk);                                 // SkToPk, draft §3.4.2

var gens = try bbs.ciphersuite.createGenerators(allocator, messages.len + 1);
defer allocator.free(gens);
const q1 = gens[0];
const h_points = gens[1..];

var scalars = try bbs.ciphersuite.messagesToScalars(allocator, messages);
defer allocator.free(scalars);

const domain = try bbs.ciphersuite.calculateDomain(allocator, pk.toBytes(), q1, h_points, header);
```

The four end-to-end functions are implemented:

```zig
const sig = try bbs.sign(allocator, sk, pk, header, messages);       // §3.5.1
const ok = try bbs.verify(allocator, pk, sig, header, messages);     // §3.5.2

// Selective disclosure: reveal only `disclosed_indexes`, hide the rest.
const rs = bbs.ciphersuite.calculateRandomScalars(5 + u, io);        // bbs.randomScalarCount(u)
const proof = try bbs.proofGen(allocator, pk, sig, header, ph, messages, disclosed_indexes, &rs);
defer allocator.free(proof);
const proof_ok = try bbs.proofVerify(allocator, pk, proof, header, ph, disclosed_messages, disclosed_indexes);
```

`Signature`/`Proof`'s `toBytes`/`fromBytes` codecs are also usable
directly (construct a value and round-trip it).

### Ciphersuites

The top-level functions are BLS12-381-SHA-256 (`bbs.sha256`). The draft's
second suite, BLS12-381-SHAKE-256, has the same four functions:

```zig
const sk = try bbs.keyGenWith(bbs.ciphersuite.Shake256, key_material, key_info, null);
const sig = try bbs.shake256.sign(allocator, sk, pk, header, messages);
const ok = try bbs.shake256.verify(allocator, pk, sig, header, messages);
// bbs.shake256.proofGen / bbs.shake256.proofVerify likewise.
```

A signature or proof made under one suite does not verify under the other.

## Randomness

`proofGen` needs fresh entropy for its blinding scalars, but takes
`random_scalars: []const Fr` as an explicit parameter rather than
reading `std.Io`/internal entropy directly — see `root.zig`'s
"Randomness" section for the full rationale. Two sources:

```zig
// Real entropy (production):
const random_scalars = bbs.ciphersuite.calculateRandomScalars(5 + u, io);

// Deterministic mock RNG (KAT reproducibility, draft §7.1):
const random_scalars = bbs.ciphersuite.mockedRandomScalars(5 + u, seed);
```

## Import graph

```
bbs → bls12_381 (G1/G2 point arithmetic, the pairing, RFC 9380 hash-to-curve)
```

`meta.deps = .{"bls12_381"}`.

## Verify

```
zig build test-bbs --summary all                    # Debug
zig build test-bbs -Doptimize=ReleaseFast --summary all
zig fmt --check modules/bbs/
```

With `gate.core_implemented = true` (current): all tests PASS
byte-exact against the embedded fixtures in both Debug and ReleaseFast —
the ciphersuite/generators/`KeyGen`/mocked-RNG vectors plus the gated
`sign`/`verify`/`proofGen`/`proofVerify` byte-exact and tamper-rejection
cases.

Provenance: see [NOTICE](NOTICE).

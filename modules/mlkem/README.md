# mlkem

**ML-KEM-512/768/1024 (FIPS 203) in pure Zig, faster than AWS-LC's AVX2 assembly on every
keygen/encaps/decaps row (0.48–0.76×), 2.5–3.8× faster than Zig std's `ml_kem`.**
std's ML-KEM made tls13's post-quantum groups 2.0–2.3× slower than AWS-LC. This module keeps
std's API shape (`std.crypto.kem.ml_kem.MLKem*`), so a consumer swaps a type, and replaces the
inside: the ring arithmetic runs on 16-lane `i16` vectors (one AVX2 register; LLVM lowers the
same code to SSE2/NEON elsewhere), the NTT-domain layout is deinterleaved so the base-case
multiplication needs no shuffles, and the matrix and noise samplers run four SHAKE streams at once
on a `@Vector(4, u64)` Keccak.

- **Model after:** FIPS 203 (algorithms), std's `ml_kem.nist` (API); pq-crystals Kyber AVX2 and
  mlkem-native studied as design references (no code taken); OpenSSL 3.5 as the reference
  implementation and live oracle, AWS-LC (mlkem-native) as the fastest in the field.
- **Platform:** any (portable Zig vectors; no assembly). **Role:** crypto primitive.
  **Concurrency:** reentrant. **Deps:** `entropy` (fail-closed draws).

## Usage

```zig
const mlkem = @import("mlkem");
const K = mlkem.MLKem768;

// Receiver: a key pair. `tryGenerate` returns entropy failure as an error and can run the
// FIPS 140-3 pairwise consistency test; `generate` is std's infallible shape (aborts instead).
const kp = try K.KeyPair.tryGenerate(io, .{ .pairwise_check = true });
const ek = kp.public_key.toBytes(); // 1184 bytes, sent to the peer

// Sender: import the encapsulation key (FIPS 203 §7.2 modulus check) and encapsulate.
const pk = try K.PublicKey.fromBytes(&ek);
const enc = try pk.tryEncaps(io); // .ciphertext to the receiver, .shared_secret kept

// Receiver: decapsulate. Never fails; an invalid ciphertext yields the implicit-rejection key.
const ss = kp.secret_key.decaps(&enc.ciphertext); // == enc.shared_secret

// Private key storage: the 64-byte seed d ‖ z (Go / BoringSSL / RustCrypto / OpenSSL form) …
const seed = kp.secret_key.seedBytes().?;
const again = K.KeyPair.generateDeterministic(seed);
// … or the FIPS 203 expanded form, imported with the §7.3 hash check.
const sk = try K.SecretKey.fromBytes(&kp.secret_key.toBytes());
```

Differences from std: keys and ciphertexts go by pointer; `decaps` returns the key directly (no
error union — implicit rejection cannot fail); `SecretKey.fromBytes` performs the FIPS 203 §7.3
hash check (`error.InconsistentKey`); a generated `SecretKey` keeps its seed; random draws are
fail-closed. `encapsDeterministic` and `generateDeterministic` are FIPS 203's `_internal`
functions: for known-answer tests, seed-form import, and protocols that derive their randomness.

Size note: like std, a `PublicKey` caches the expanded matrix Âᵀ (k² · 512 bytes: 8 KiB for
ML-KEM-1024) and a `SecretKey` embeds the public key, so these are large values — keep them by
pointer.

## Tests and tools

`zig build test-mlkem`: byte-identity with std on random seeds, NIST ACVP-Server keyGen / encaps /
decaps / key-check vectors, Wycheproof (rejection-heavy matrices, malleable ciphertexts, key
corruption), the C2SP CCTV modulus vectors (all 2592 bad encapsulation keys), an accumulated
differential stream against std (`MLKEM_ACCUM=N`), the NTT against a scalar reference and the
schoolbook product, exhaustive compression rounding, 4-way Keccak against std, and the fuzz
harness's reach test. Fuzz verdict: `MLKEM_FUZZ=<runs>[,<seed>]` on the ReleaseSafe test binary.
Constant time: `scripts/checks/ctgrind.sh mlkem`. Bench: `zig build bench-mlkem` (ours, std,
OpenSSL 3.5, aws-lc-rs). Live oracle: `zig build interop-mlkem`.

Provenance: original work of the zig-libs authors (MIT), written from FIPS 203 and FIPS 202;
pq-crystals Kyber AVX2 (CC0 / Apache-2.0) and mlkem-native (Apache-2.0 / ISC / MIT) were studied
as design references for the deinterleaved NTT layout and the batched Keccak — no code ported, no
licence condition. Test data reproduced from upstream: NIST ACVP-Server (US Government
work), C2SP CCTV (CC0-1.0) and Wycheproof (Apache-2.0, conditions in [`NOTICE`](NOTICE)); see
`tools/vectors/extract.py` for the recipe and `SPEC.md`.

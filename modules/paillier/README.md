# paillier

Pure-Zig Paillier additively-homomorphic public-key cryptosystem (Paillier
1999), built on `std.crypto.ff` — no bignum reimplementation, no libc, no
`@cImport`.

**Status: IMPLEMENTED (I2 Phase 1 complete).** Keygen (`generate` with a
Miller-Rabin probable-prime search, `fromPrimes` for deterministic/KAT
construction), `encrypt`/`decrypt`, and the homomorphic ops
(`addCiphertexts`/`addPlaintext`/`mulPlaintext`) are all real.
`zig build test-paillier` is green in Debug and ReleaseFast,
cross-checked value-exact against `phe` (python-paillier) 1.5.0 toy-key
vectors plus self-checking round-trip/homomorphic-property tests and real
512-/2048-bit `generate` round trips — see SPEC.md "Verification".

Paillier is the additively-homomorphic sub-primitive the GG20/CMP
threshold-ECDSA protocol's MtA (multiplicative-to-additive) step builds on —
this module is Phase 1 of that arc (core PKE only). The zero-knowledge
proofs threshold-ECDSA actually needs around it (proof of correct
encryption, range proofs, MtA itself) are Phase 2, a separate later module —
see SPEC.md "Phase-2 boundary".

- **Model after:** P. Paillier, "Public-Key Cryptosystems Based on Composite
  Degree Residuosity Classes", EUROCRYPT 1999 — the standard `g = n+1`
  variant. Built on `std.crypto.ff` exactly like this repo's `rsa` module
  (`Uint`/`Modulus`/`Fe`, the same fixed-width constant-time modular-
  arithmetic primitive).
- **Platform:** any. **Role:** util (pure computation, no I/O of its own).
  **Concurrency:** reentrant — `PublicKey`/`SecretKey`/`Ciphertext` are plain
  value types, no shared/global state.
- **Modulus size:** designed for a 2048-bit `n` (`modulus_bits`), needing
  4096 bits of headroom for `n²` (`max_bits`) — see SPEC.md.

## Provenance

Clean-room implementation from the public Paillier 1999 paper (P. Paillier,
"Public-Key Cryptosystems Based on Composite Degree Residuosity Classes",
EUROCRYPT 1999) — a public academic publication, not a copyrightable
implementation; no third-party source ported or consulted for design (see
`CONVENTIONS.md` §5 / root `NOTICE` §0 policy).

Test-vector cross-check only, **not** a design reference: the `round-trip` /
`homomorphic properties` unit tests in `src/root.zig` use a small fixed toy key
(p=11, q=17) with concrete `(m, r) -> ciphertext` vectors independently
recomputed in Python and cross-checked against `phe` (python-paillier) 1.5.0,
PyPI, BSD-licensed (github.com/data61/python-paillier) — specifically
`PaillierPublicKey.raw_encrypt` / `PaillierPrivateKey.raw_decrypt` called with
an explicit `r_value`, which implements the same `g = n+1` standard variant this
module uses. No `phe` source was ported; it was exercised only as a black-box
vector oracle, the same relationship root `NOTICE` §0 describes for `tar`/`nft`
— recorded because a specific version and vector-generation method is a fact
worth pinning for anyone re-deriving the vectors.
## API

```zig
const paillier = @import("paillier");

const kp = try paillier.fromPrimes(p_bytes, q_bytes); // deterministic (KAT/testing)
// const kp = try paillier.generate(random, paillier.modulus_bits); // random

const pk: paillier.PublicKey = kp.public;   // n, n_sq (=n²), g
const sk: paillier.SecretKey = kp.secret;   // n, n_sq, lambda, mu

// m/r must be constructed canonical mod `pk.n_sq` — see the "Fe
// construction contract" note at the top of src/root.zig.
const m = try paillier.Fe.fromPrimitive(u32, pk.n_sq, 42);
const r = try paillier.Fe.fromPrimitive(u32, pk.n_sq, 7);
const c = try paillier.encrypt(pk, m, r);
// const c = try paillier.encryptRandom(pk, m, random); // samples r itself

const plaintext = try paillier.decrypt(sk, c); // rejects c=0/non-units as InvalidCiphertext

// The whole point: homomorphic ops.
const c_sum = paillier.addCiphertexts(pk, c1, c2);       // E(m1+m2 mod n)
const c_sum2 = try paillier.addPlaintext(pk, c1, m2);    // E(m1+m2 mod n)
const c_scaled = try paillier.mulPlaintext(pk, c1, k);   // E(k*m1 mod n)

// Serialization (real, mechanical — works today, no stub involved):
var n_buf: [paillier.modulus_bytes]u8 = undefined;
try pk.nToBytes(&n_buf);
const pk2 = try paillier.PublicKey.fromBytes(&n_buf, null); // g = n+1 re-derived
```

See `src/root.zig` for the full API and the `std.crypto.ff` integration
notes — most notably the "Fe construction contract" at the top of the file
(construct plaintext/randomness `Fe`s against `pk.n_sq`, never `pk.n`), and
how the `m = 0`/`k = 0` valid-plaintext cases are handled around `ff`'s
`NullExponentError` zero-exponent guard (the standard `g = n+1` path uses
the binomial identity `g^m ≡ 1 + m·n (mod n²)`, which needs no exponent at
all — see SPEC.md).

## Backlog

- Minimum-key-size floor on `PublicKey.fromBytes`/`SecretKey.fromBytes`
  (see SPEC.md "Backlog / deferred").
- Phase 2 (separate later module): the GG20/CMP zero-knowledge proofs and
  MtA protocol layered on top of this core PKE.

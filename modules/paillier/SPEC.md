# paillier — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see
./README.md "Provenance" + /NOTICE.

## Design & invariants

**IMPLEMENTED (I2 Phase 1 complete).** `PublicKey` (`n`, `n_sq`, `g`), `SecretKey` (`n`,
`n_sq`, `lambda`, `mu`), and `Ciphertext` (`c`) with real `fromBytes`/`toBytes`
serialization, plus the full number-theoretic core: `fromPrimes` (n = p·q, λ = lcm(p−1,q−1),
g = n+1, μ = L(g^λ mod n²)⁻¹ mod n with L(x) = (x−1)/n exact), `generate` (sieve +
Miller-Rabin probable-prime search mirroring `rsa.generate`, minus its `e`-coprimality
filter), `encrypt`/`decrypt`, and the three homomorphic ops. Everything is `std.crypto.ff`
(`Uint`/`Modulus`/`Fe` at `max_bits = 4096`) with `std.math.big.int` only for the one-off
derivations `ff` has no primitive for (gcd/lcm, extended-Euclid inverse, the exact L
division).

**The `g = n+1` binomial shortcut.** For the standard generator the binomial theorem
collapses `(1+n)^m = Σ C(m,k)·n^k ≡ 1 + m·n (mod n²)` (every k ≥ 2 term carries an n²
factor), so `encrypt`/`addPlaintext`'s `g^m` term is one constant-time `mul` + `add`
instead of a modexp (`gPow` in `src/root.zig`). This also makes `m = 0` fall out for free
(1 + 0·n = 1) with no data-dependent branch, and means a possibly-secret plaintext `m`
never enters a bit-scanned exponent path at all on the standard-`g` path. A
caller-supplied non-standard `g` (`PublicKey.fromBytes` with explicit `g_bytes`) falls
back to the general constant-time `pow` with `g^0 = 1` special-cased.

**Modulus size.** `modulus_bits = 2048` (two 1024-bit primes `p`,`q`) is the size this
module is designed and sized for — comparable to this repo's `rsa` module's default RSA
key size. `max_bits = 4096` is the ceiling the fixed-width `Uint`/`Modulus`/`Fe` types
(`std.crypto.ff.Uint(max_bits)` etc.) are sized to, since every `n²`-modulus value needs
double `n`'s width. `generate`/`fromPrimes` are not hard-capped to exactly 2048 bits (they
accept any `p`,`q` whose product fits `max_bits`, e.g. much smaller ones for KATs) — no
minimum-key-size floor is enforced yet (unlike `rsa`'s 512-bit floor on `PublicKey.fromBytes`);
see "Backlog" below.

**The `std.crypto.ff` Fe-widening trap (the single most important integration note for the
implementer).** `Modulus.shrink` — which every `Fe` construction/Montgomery conversion calls
internally — only ever *narrows* a value's active limb count down to the calling modulus's
width; it errors (`error.Overflow`) if asked to *widen* a value that was already shrunk
against a smaller modulus. Concretely: an `Fe` built via `Fe.fromBytes(pk.n, bytes, .big)` (or
`Fe.fromPrimitive(T, pk.n, x)`) is shrunk to `pk.n`'s (smaller) limb count, and passing that
same value as a base/exponent into an `pk.n_sq`-modulus operation (`pk.n_sq.pow(...)`,
`pk.n_sq.mul(...)`) will fail. The fix used throughout this module: construct any value that
will be used under the `n_sq` modulus — plaintexts and randomness fed to `encrypt`, the
plaintext operand fed to `addPlaintext`/`mulPlaintext` — directly against `n_sq`
(`Fe.fromBytes(pk.n_sq, ...)`/`Fe.fromPrimitive(T, pk.n_sq, x)`), never against `pk.n`. Since
every value `< n` is automatically `< n²` too, this is always safe and costs nothing; it is
purely a construction-site discipline, spelled out in full at the top of `src/root.zig` (the
"Fe construction contract") and repeated at each affected function.

**The `NullExponentError` zero-plaintext trap.** `std.crypto.ff.Modulus.pow`/`powPublic`
deliberately reject an all-zero exponent (`error.NullExponent`) as a near-certain caller bug.
`m = 0` and `k = 0` are perfectly valid Paillier plaintexts/scalars (`E(0)`, `E(m)^0 = E(0)`).
Handled: `encrypt`/`addPlaintext`'s `g^m` needs no special case on the standard-`g` binomial
path (see above) and returns `one()` for `m = 0` under a non-standard `g`; `mulPlaintext`
special-cases `k = 0` to `one()` — `c^0 = 1` is the deterministic, unblinded `E(0)`
(`L(1^λ) = 0`), exactly what `phe`'s `raw_mul` (python `pow(c, 0, n²) = 1`) produces.

**Constant-time discipline.** Mirrors `rsa`'s stance:

- `decrypt`'s `c^λ mod n²` and `mulPlaintext`'s `c^k mod n²` use `Modulus.pow`
  (constant-time Montgomery ladder) — `λ` is secret-key material, `k` may be a secret
  scalar. `fromPrimes`'s `g^λ mod n²` likewise uses `pow`, never `powPublic` (`λ` is
  factorization-equivalent).
- `encrypt`'s `r^n` term uses `powPublic`: the exponent `n` is the public modulus, and
  `powPublic` remains constant-time with respect to the base `r`.
- `fromPrimes`'s one-time key derivation drops to `std.math.big.int`
  (variable-time extended-Euclid/gcd/lcm, exactly like `rsa.fromPrimesImpl` does for its
  own `d = e⁻¹ mod λ(n)`) — a one-time key-import cost, not a per-operation leak, same
  rationale as `rsa`'s SPEC.md.
- **Known caveat:** `decrypt`'s L-function drops to `std.math.big.int` for the exact
  `(x−1)/n` division (`ff` has no exact-division primitive), and that division is
  variable-time in `x` — a per-decryption, plaintext-derived value. The limb *widths* are
  fixed by the key size (the dominant cost driver in `std.math.big.int`'s schoolbook
  division), so the residual signal is small, but it is not the hard constant-time
  guarantee the modexp has. Callers running in an environment with a co-located attacker
  measuring single decryptions should be aware; a constant-time exact division is future
  work if a consumer ever needs it.
- Prime generation (`generate`) is inherently variable-time in how *long* the search
  takes (every implementation's is); the Miller-Rabin modexps use `ff`'s constant-time
  path and all candidate buffers are `secureZero`ed — same posture as `rsa`.

**Semantic security relies on the randomness `r`.** Paillier is IND-CPA secure only because
each encryption draws a fresh, uniform `r` coprime to `n`; `encrypt` accepts a caller-supplied
`r` specifically so KATs/tests are reproducible — production callers MUST use
`encryptRandom` (or draw `r` with equivalent care) for every real encryption. Reusing an `r`,
or drawing it from a weak/predictable source, breaks semantic security exactly as reusing a
nonce would for a symmetric AEAD.

**`gcd(r, n) = 1` is not checked.** `encryptRandom`'s rejection sampling draws `r` uniformly
from `[1, n)` without verifying it is coprime to `n`; for `n = p*q` with large random primes
the probability a uniform `r` collides with a factor is `~1/p + 1/q`, i.e. negligible, and
this matches common reference implementations (including `phe`/python-paillier, which this
module's KAT vectors are cross-checked against — see `NOTICE`). Documented here rather than
silently assumed.

## Threat model / out of scope

- **Key strength = factoring `n`,** exactly like RSA. `generate` draws two `bits/2`-bit
  probable primes (top two bits set → `n` is exactly `bits` bits; 64 Miller-Rabin rounds →
  ≤ 2⁻¹²⁸ worst-case acceptance error per prime; FIPS 186-5 §A.1.3 top-100-bits closeness
  guard against Fermat factorization — all inherited from `rsa`'s search). A weak or
  attacker-influenced `random` breaks everything; the API takes `std.Random` and trusts it.
- **`fromPrimes` trusts its factors.** It runs no primality test (that is `generate`'s
  job); its self-checks (odd `n`, L-exactness of `g^λ`, invertibility of `μ`) reject many
  composites but NOT all — a key derived from composite factors silently decrypts garbage
  for most plaintexts. Deterministic construction is for KATs/round-tripping stored keys.
- **Timing:** see "Constant-time discipline" above (secret-exponent modexps constant-time;
  decrypt's L-division and keygen's big.int derivation variable-time with documented
  rationale).
- **Malicious-ciphertext robustness is NOT provided.** `decrypt` rejects the cheaply
  detectable garbage (`c = 0`, non-units mod `n`, anything failing `x ≡ 1 (mod n)`), but
  Paillier ciphertexts are malleable *by design* (that's the feature) — nothing here
  authenticates who formed a ciphertext or proves its plaintext is in range. That is
  exactly the Phase-2 ZK-proof layer (below).
- **`decrypt` as an oracle:** `error.InvalidCiphertext` deliberately does not distinguish
  *why* a ciphertext was rejected (zero / non-unit / exactness failure), and honest
  ciphertexts never fail, so the error channel leaks nothing about the key beyond
  "attacker-crafted non-unit", which the attacker already knew.

### Phase-2 boundary (deliberately out of scope here)

GG20/CMP threshold-ECDSA does not use raw Paillier ciphertexts directly — it wraps every
encryption/homomorphic-combination step in a zero-knowledge proof so a malicious co-signer
can't inject a crafted ciphertext (out-of-range plaintext, wrong-key ciphertext, etc.) into
the protocol. None of that is in this module:

- **Proof of correct Paillier encryption** (that a given ciphertext really does encrypt a
  plaintext the prover knows, in-range) — Phase 2.
- **Range proofs** bounding a plaintext/randomness to a claimed interval — Phase 2.
- **MtA (multiplicative-to-additive)** — the protocol that composes `addPlaintext` +
  `mulPlaintext` + `addCiphertexts` (plus the proofs above) into a secure two-party share
  conversion — Phase 2, and the actual reason threshold-ECDSA wants Paillier in the first
  place.

These belong in a separate, later module that depends on this one (`paillier`), not here —
see `// TODO(phase2)` in `src/root.zig`.

## Verification

`zig build test-paillier` is **green in Debug and ReleaseFast** (CONVENTIONS.md §7
"pure logic" harness: unit tests + round-trip + property tests). The Debug run takes ~20 s,
almost all of it the full 2048-bit `generate` round-trip test (ReleaseFast runs in ~1 s).

Paillier has no official RFC/standard KAT vectors (unlike `rsa`'s RFC 8017 worked examples).
The correctness anchors, in order of strength:

- **phe cross-check (value-exact):** a small fixed key (`p=11, q=17`, `n=187` —
  intentionally toy-sized, NOT secure, chosen only to be hand-verifiable) whose derived
  `λ=80`/`g=188`/`μ=180` and concrete `(m, r) -> ciphertext` vectors (incl. `m = 0` and
  `m = n−1`, and every intermediate ciphertext of the homomorphic-property test) were
  independently cross-checked against `phe` (python-paillier) 1.5.0's
  `PaillierPublicKey.raw_encrypt`/`PaillierPrivateKey.raw_decrypt` (same `g = n+1`
  standard variant) — see `NOTICE`. No ciphertext value was fabricated.
- **Exhaustive toy round-trip:** every residue `m ∈ [0, 187)` encrypts and decrypts back
  (with `r` cycled through fixed units mod 187 — for a toy `n` a *uniform* `r` collides
  with a factor with probability ~1/p + 1/q ≈ 15%, in which case `decrypt` correctly
  rejects the non-unit ciphertext; at real key sizes that probability is negligible, see
  "gcd(r, n) is not checked" above).
- **Self-checking homomorphic properties:** `decrypt(addCiphertexts(E(m1), E(m2))) ==
  (m1+m2) mod n` (incl. wrap-around and the exact `E(n−1)+E(1) -> 0` case), same for
  `addPlaintext` (incl. `m = 0` identity) and `mulPlaintext` (incl. `k = 0 -> E(0)`,
  `k = 1` identity, wrap-around).
- **Real-size keygen:** `generate` at 512 bits (fast, every-run) and at the full
  2048 bits (slow) both round-trip encrypt/decrypt + a homomorphic op, and `n` lands on
  exactly the requested bit width.
- **Negative tests:** `fromPrimes` rejects `p == q`/degenerate/oversized factors;
  `decrypt` rejects `c = 0`, `c = n`, `c = p`; `generate` rejects invalid bit sizes.

## Backlog / deferred

- No minimum-key-size floor is enforced on `PublicKey.fromBytes`/`SecretKey.fromBytes`
  (unlike `rsa`'s 512-bit floor; `generate` does enforce `min_generate_bits = 512`) —
  consider adding one before any production use.
- Constant-time exact division for `decrypt`'s L-function (see the timing caveat above) —
  only if a consumer's threat model ever needs it.
- Phase 2 (separate later module, depends on this one): proof of correct encryption, range
  proofs, MtA — see "Phase-2 boundary" above.

## Status

`gap · any · util · reentrant` + deps: none (`std.crypto.ff` only) — canonical source is
`pub const meta` in `src/root.zig`. ("`gap`" is this repo's catalog-maturity vocabulary for
a std-gap module built from scratch, same as `rsa`'s SPEC.md — see CONVENTIONS.md's `meta`
tag vocabulary discussion for why there's no separate dedicated "status" tag.)

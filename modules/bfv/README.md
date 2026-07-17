# bfv — leveled BFV homomorphic encryption (Parts 1–2: backbone + keyGen/encrypt/decrypt)

**Fully Homomorphic Encryption.** FHE lets you compute directly on ciphertexts:
`Dec(f(Enc(x))) = f(x)`, so an untrusted party can evaluate a function over data
it can never read. BFV (Fan–Vercauteren, ePrint 2012/144) is the cleanest
**exact-integer** scheme — no CKKS-style approximate rescaling — and matches
Microsoft SEAL's default, making it cross-checkable. This module targets a
*leveled* BFV that can homomorphically **add** and **multiply** to a bounded
multiplicative depth (no bootstrapping). This is a first-in-pure-Zig
capability: `std` ships lattice KEM/signatures (ML-KEM/ML-DSA) but no
homomorphic-evaluation scheme, and the sibling `paillier` is only additively
homomorphic — BFV adds the multiply.

FHE is large, so it is built as a multi-part arc. **Parts 1–2 are real: the
arithmetic backbone (byte-exact-KAT'd) and the BFV scheme core —
`keyGen`/`encrypt`/`decrypt`.** Part 3 (the genuinely hard, noise-sensitive
`mul`/`relinearize`/`noiseBudget`) stays gated (see below).

## What is real today (Part 1)

The whole computational backbone FHE stands on is implemented and tested:

| Piece | File | What |
|---|---|---|
| Modular arithmetic | `modarith.zig` | word-size ops mod an NTT prime `q<2^62`: `mulMod`/`powMod`/`invMod`, deterministic Miller-Rabin `isPrime`, `primitive2NthRoot` |
| Negacyclic NTT | `ntt.zig` | `Ntt(N)` — Cooley-Tukey forward / Gentleman-Sande inverse over `Z_q[X]/(X^N+1)`; `mulNegacyclic` (O(N log N)) + `mulSchoolbook` (the independent O(N²) cross-check) |
| RNS / CRT | `rns.zig` | `Basis` — residue representation of `q=∏qᵢ`, exact CRT reconstruct, exact base conversion |
| RLWE ring | `ring.zig` | `RnsPoly(N,L)` — `R_q` add/negate/NTT/pointwise-multiply |
| Plaintext | `encode.zig` | `Plaintext(N)` — `R_t` coefficient + integer encodings, `addRef`/`mulRef` references |
| Parameters | `params.zig` | `Params` + NTT-friendly-prime validation; `test_tiny`, `bfv_toy` sets |

## The scheme core (Part 2) + the still-gated core (Part 3)

`bfv.Bfv(P)` exposes the scheme, controlled by two honestly-separated flags in
`gate.zig`:

- `scheme_core_implemented` = **`true`** — **Part 2 (Opus), REAL:** `keyGen`
  (`pk=(−(a·s+e), a)`, ternary `s`) / `encrypt` (`c0=Δ·m+p0·u+e0`, `c1=p1·u+e1`,
  `Δ=⌊q/t⌋`) / `decrypt` (`⌊t/q·(c0+c1·s)⌉ mod t`, exact CRT reconstruction +
  round-half-up rescale). Anchored by a deterministic noiseless-ciphertext
  decrypt KAT, the enc/dec round-trip (tiny + N=1024), and homomorphic-add
  end-to-end.
- `fable_core_implemented` = **`false`** — **Part 3 (Fable):** `mul` (tensor +
  `⌊t/q·…⌉` rescale) / `relinearize` (relin-key key-switch) / `noiseBudget`. The
  noise-management core (see `SPEC.md`). Its cores `@panic` and the dependent
  mul/depth end-to-end tests report SKIP (a skip is not a green light).

## Usage

```zig
const bfv = @import("bfv");

// Arithmetic backbone is usable standalone today:
const T = bfv.Ntt(1024);
const engine = try T.init(1073750017); // prime ≡ 1 mod 2048
const product = engine.mulNegacyclic(a, b); // a·b mod (X^1024 + 1)

// Scheme surface (cores land in Parts 2–3):
const B = bfv.Bfv(bfv.params.bfv_toy);
const inst = try B.init();
const kp = inst.keyGen(rand);              // Part 2 (real)
const ct = inst.encrypt(&kp.pk, &pt, rand);
const back = inst.decrypt(&kp.sk, &ct);    // Dec(Enc(m)) == m
const sum = inst.add(&ct, &ct2);           // homomorphic add (real)
// inst.mul / relinearize / noiseBudget    → Part 3 (gated)
```

## Verify

```
zig build test-bfv --summary all                    # Debug
zig build test-bfv -Doptimize=ReleaseFast --summary all
```

Parts 1–2: 32 pass / 2 skip (the 2 SKIPs are the mul+relin and multiply-depth
anchors, which switch on with the Part-3 Fable core). The passing set includes
the byte-exact NTT + RNS KATs, two deliberately-broken positive controls (a
cyclic-vs-negacyclic discriminator and a wrong-scale "encryptor"), a
deterministic noiseless-ciphertext decrypt KAT, and the enc/dec round-trip +
homomorphic-add end-to-end anchors (tiny params + N=1024).

Provenance: clean-room from the Fan–Vercauteren paper + public NTT/RNS/BFV
design (SEAL); no third-party source ported — see `SPEC.md`. NTT/RNS KAT vectors
come from an independent Python re-derivation (`SPEC.md` "External-reference
anchoring"). No `NOTICE` entry required (CONVENTIONS.md §5).

# bfv — leveled BFV homomorphic encryption (complete: add + multiply to depth)

**Fully Homomorphic Encryption.** FHE lets you compute directly on ciphertexts:
`Dec(f(Enc(x))) = f(x)`, so an untrusted party can evaluate a function over data
it can never read. BFV (Fan–Vercauteren, ePrint 2012/144) is the cleanest
**exact-integer** scheme — no CKKS-style approximate rescaling — and matches
Microsoft SEAL's default parameter/NTT design, which makes it cross-checkable
**in principle** against SEAL (small fix-space, deterministic construction).
**No SEAL vectors have actually been produced or checked in** —
`modules/bfv/data/` is empty; what validates the scheme today is
`Dec(Enc(x)) == x` and the homomorphic property against this module's own
reference helpers (see "Verification" below). This module targets a
*leveled* BFV that can homomorphically **add** and **multiply** to a bounded
multiplicative depth (no bootstrapping). This is a first-in-pure-Zig
capability: `std` ships lattice KEM/signatures (ML-KEM/ML-DSA) but no
homomorphic-evaluation scheme, and the sibling `paillier` is only additively
homomorphic — BFV adds the multiply.

FHE is large, so it was built as a multi-part arc — **all three parts are now
real:** the arithmetic backbone (byte-exact-KAT'd), the BFV scheme core
(`keyGen`/`encrypt`/`decrypt`), and the noise-management core (`mul` /
`genRelinKey`/`relinearize` / `noiseBudget`). Toy/test parameters only — no
security level is claimed, and no bootstrapping (leveled depth only).

## What is real today (Part 1)

The whole computational backbone FHE stands on is implemented and tested:

| Piece | File | What |
|---|---|---|
| Modular arithmetic | `modarith.zig` | word-size ops mod an NTT prime `q<2^62`: division-free `Modulus` (Barrett) + `Shoup` (fixed multiplier) for the hot paths, `mulMod` (the `%q` division) retained as their differential oracle and for cold setup; `powMod`/`invMod`, deterministic Miller-Rabin `isPrime`, `primitive2NthRoot` |
| Negacyclic NTT | `ntt.zig` | `Ntt(N)` — Cooley-Tukey forward / Gentleman-Sande inverse over `Z_q[X]/(X^N+1)` with Shoup butterflies; `mulNegacyclic` (O(N log N)) + `mulSchoolbook` (the independent O(N²) cross-check); `forwardRef`/`inverseRef` keep the original division-based bodies as the differential oracle |
| RNS / CRT | `rns.zig` | `Basis` — residue representation of `q=∏qᵢ`, exact CRT reconstruct, exact base conversion. `Bfv` hoists the same CRT constants to `init` (`Bfv.reconstruct`) and keeps `Basis.reconstruct` as its oracle |
| RLWE ring | `ring.zig` | `RnsPoly(N,L)` — `R_q` add/negate/NTT/pointwise-multiply |
| Plaintext | `encode.zig` | `Plaintext(N)` — `R_t` coefficient + integer encodings, `addRef`/`mulRef` references |
| Parameters | `params.zig` | `Params` + NTT-friendly-prime validation; toy sets `test_tiny`, `bfv_toy`, `test_mul`, plus the security-grade `sec_n8192_logq218` (`N=8192`, `log2 q=218`, `t=65537`) |
| Benchmarks | `bench.zig` | old-path-vs-new-path ns/op, opt-in: `BFV_BENCH=1 zig build test-bfv -Doptimize=ReleaseFast` |

## The scheme core (Part 2) + the Fable core (Part 3)

`bfv.Bfv(P)` exposes the scheme; both flags in `gate.zig` are now **`true`**:

- `scheme_core_implemented` = **`true`** — **Part 2 (Opus), REAL:** `keyGen`
  (`pk=(−(a·s+e), a)`, ternary `s`) / `encrypt` (`c0=Δ·m+p0·u+e0`, `c1=p1·u+e1`,
  `Δ=⌊q/t⌋`) / `decrypt` (`⌊t/q·(c0+c1·s)⌉ mod t`, exact CRT reconstruction +
  round-half-up rescale). Anchored by a deterministic noiseless-ciphertext
  decrypt KAT, the enc/dec round-trip (tiny + N=1024), and homomorphic-add
  end-to-end.
- `fable_core_implemented` = **`true`** — **Part 3 (Fable), REAL:** `mul`
  (exact integer tensor + `⌊t/q·…⌉` rescale) / `genRelinKey`+`relinearize`
  (base-`2^8` gadget key-switch for `s²`) / `noiseBudget`. Anchored by the
  mul+relin and multiply-DEPTH (`a·b·c`) end-to-end tests over random AND
  boundary plaintexts on `params.test_mul`, whose worst-case noise ledger
  makes depth-2 correctness a guarantee for every seed — see `SPEC.md`
  "Part-3 multiply" for the design and the noise argument.

## Usage

```zig
const bfv = @import("bfv");

// Arithmetic backbone is usable standalone today:
const T = bfv.Ntt(1024);
const engine = try T.init(1073750017); // prime ≡ 1 mod 2048
const product = engine.mulNegacyclic(a, b); // a·b mod (X^1024 + 1)

// Scheme surface (complete). `io` is a `std.Io`: key generation, encryption and
// the relin key draw through `entropy.SecureSource`, the fail-closed adapter
// over `std.Io.randomSecure` (see the "Randomness" note in `src/bfv.zig`) —
// not the silently-degrading `std.Io.random`. Still far better than a bare
// `std.Random` parameter, which would accept `DefaultPrng.init(0)` at a call
// site that looks identical, and with `u,e0,e1` predictable
// `c0 − p0·u − e0 = Δ·m` recovers the plaintext WITHOUT the secret key. The
// `…ForTest` twins take a `std.Random` for KAT reproducibility.
const B = bfv.Bfv(bfv.params.test_mul);
const inst = try B.init();
const kp = inst.keyGen(io);
const rlk = inst.genRelinKey(&kp.sk, io);
const ca = inst.encrypt(&kp.pk, &pa, io);
const cb = inst.encrypt(&kp.pk, &pb, io);
const sum = inst.add(&ca, &cb);                   // Dec == a+b (mod t)
const prod = inst.relinearize(&inst.mul(&ca, &cb), &rlk); // Dec == a·b (mod t)
const bits_left = inst.noiseBudget(&kp.sk, &prod); // remaining headroom (bits)
```

## Verify

```
zig build test-bfv --summary all                    # Debug
zig build test-bfv -Doptimize=ReleaseFast --summary all
```

Parts 1–3: green in Debug and ReleaseFast. The set includes the
byte-exact NTT + RNS KATs, three deliberately-broken positive controls (a
cyclic-vs-negacyclic discriminator, a wrong-scale "encryptor", and a
corrupted-relin-key catch), a deterministic noiseless-ciphertext decrypt KAT
with margin-boundary teeth, the enc/dec round-trip + homomorphic-add anchors
(tiny params + N=1024), and the Part-3 mul+relin and multiply-DEPTH anchors
over random + boundary plaintexts on `test_mul`.

Provenance: clean-room from the Fan–Vercauteren paper + public NTT/RNS/BFV
design (SEAL); no third-party source ported — see `SPEC.md`. NTT/RNS KAT vectors
come from an independent Python re-derivation (`SPEC.md` "External-reference
anchoring"). No `NOTICE` entry required (CONVENTIONS.md §5).

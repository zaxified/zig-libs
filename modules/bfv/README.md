# bfv — leveled BFV homomorphic encryption (Part 1: arithmetic backbone + scheme scaffold)

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

FHE is large, so it is built as a multi-part arc. **This is Part 1: the
arithmetic backbone (real + byte-exact-KAT'd) plus the scaffolded scheme
surface.** The genuinely hard, noise-sensitive scheme core is gated (see below).

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

## What is scaffolded (gated cores)

`bfv.Bfv(P)` exposes the scheme. Its types, byte codecs, and the
(non-noise-sensitive) homomorphic `add`/`sub` are **real**; the cores are gated
in `gate.zig` behind two honestly-separated flags:

- `scheme_core_implemented` — **Part 2 (Opus):** `keyGen` / `encrypt` /
  `decrypt`. Textbook leveled-BFV, byte-exact-KAT-able against SEAL.
- `fable_core_implemented` — **Part 3 (Fable):** `mul` (tensor + `⌊t/q·…⌉`
  rescale) / `relinearize` (relin-key key-switch) / `noiseBudget`. The
  noise-management core (see `SPEC.md`).

While a flag is `false` its cores `@panic` and the dependent end-to-end tests
report SKIP (a skip is not a green light).

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
// inst.keyGen / encrypt / decrypt  → Part 2
// inst.mul / relinearize           → Part 3
```

## Verify

```
zig build test-bfv --summary all                    # Debug
zig build test-bfv -Doptimize=ReleaseFast --summary all
```

Part 1: 29 pass / 3 skip (the SKIPs are the homomorphic end-to-end anchors,
which switch on with the scheme cores). The passing set includes the byte-exact
NTT + RNS KATs and two deliberately-broken positive controls (a
cyclic-vs-negacyclic discriminator and a wrong-scale "encryptor") that prove the
harness bites before any scheme core exists.

Provenance: clean-room from the Fan–Vercauteren paper + public NTT/RNS/BFV
design (SEAL); no third-party source ported — see `SPEC.md`. NTT/RNS KAT vectors
come from an independent Python re-derivation (`SPEC.md` "External-reference
anchoring"). No `NOTICE` entry required (CONVENTIONS.md §5).

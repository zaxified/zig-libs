# p256 — design & threat model

Auditor/design reference. Module purpose + API live in `README.md`; meta tags
live in `src/root.zig`'s `pub const meta`. This file covers the design decisions,
the constant-time contract, and the two gated Fable cores.

## Dedup — why this module exists although std HAS P-256

std ships `std.crypto.ecc.P256`, so p256 is **not** a std-gap fill in the usual
sense. It is a deliberate **performance-specialized reimplementation**, justified
by two facts:

1. **Measured gap.** std's curve is portable pure-Zig (a fiat-crypto Montgomery
   field, no asm, no endomorphism, a generic windowed ladder), which the repo
   audit measured at **~16× ECDSA-P256 sign / ~9× verify slower than OpenSSL's
   nistz256** (`~/CML/audit/modules/ctap2pin.md`, `perf/bignum-std.md`). That sits
   on the P2 internet-facing HTTPS-API hot path (JWT ES256 verify per request,
   TLS), on 2FA/WebAuthn (`ctap2pin`), `spake2plus`, and the P-256 suites of
   `hpke`/`voprf`/`mls`/`jwe` — all of which ride `std.crypto.ecc.P256`, and we
   cannot patch std.
2. **The collection's thesis.** zig-libs exists so native Zig is usable INSTEAD
   of linking a C library. A P-256 within a small factor of nistz256 — while
   staying zero-C/no-libc — is exactly that thesis applied to the second most
   deployed curve in the repo (after secp256k1 / `k256`).

The realistic target is **~2–3× OpenSSL nistz256**, the same ballpark the sibling
`k256` arc reached vs libsecp256k1. Parity with decades-tuned asm-grade C is
explicitly a non-goal.

This module is the direct P-256 analogue of `k256` and REUSES its structure (the
gated-core split, the portable-oracle/asm-differential harness, the
`blackBox`-guarded constant-time masked scan). The P-256-specific differences are
called out below.

## Field representation — four full 2^64 limbs

`Fe` stores the base-field value as **four full 2^64 little-endian limbs**
(`[4]u64`), always canonical (`< p`) between operations, **NORMAL domain** (not
Montgomery — the special reduction is used directly, as nistz256 does for its
field). The API mirrors `std.crypto.ecc.P256.Fe` method-for-method, so `group.zig`
is a drop-in and the oracle differential is a direct `p256.Fe.op == std.Fe.op`
comparison via `toBytes` (both representations serialise to the same canonical
integer regardless of internal domain).

### The special-prime (Solinas) reduction — the curve-specific, Fable-hard part

P-256's prime is the NIST/nistz256 Solinas prime
`p = 2^256 − 2^224 + 2^192 + 2^96 − 1`, so
`2^256 ≡ M (mod p)` with `M = 2^224 − 2^192 − 2^96 + 1`.

This is where P-256 **differs sharply from secp256k1**. k256's fold multiplier is
the *tiny* `c = 2^32 + 977`, so each fold is a single narrow multiply and ~4 folds
reach `< 2^256`. P-256's `M` is ~2^224 — a **wide** multiply — and each fold shrinks
the high part by only ~32 bits, so the portable oracle folds **eleven** times
(`field.reduceWide`, `x = (x mod 2^256) + M·(x ≫ 256)`), reaching `< 2^257` (at
most one excess bit; asserted), then `normalize` folds the final carry bit twice
(the first fold of the top bit can re-overflow 2^256; the second cannot, because
the wrapped low word is then `< M < 2^224`) and does one masked conditional
subtract of `p`. The 11-fold portable reduction was validated against a bignum
`% p` oracle on 2,000,000 random full-512-bit inputs plus edges before the module
was written.

**Carry propagation in this fold is the classic error-prone spot** and the reason
this reduction is the Fable-hard core: the gated `MULX/ADX` version
(`fast_core.fieldMul`/`fieldSq`, a panic stub in this scaffold) must reproduce the
SAME reduction on explicit 64-bit limbs. Two equivalent limb-level shapes for the
Fable author (documented in `fast_core.zig`):

- **wide-fold** — mirror `reduceWide` limb-by-limb (`lo += M·hi`); simplest, but
  many folds and a wide `M`-multiply each time.
- **word-shuffle (classic nistz256)** — express the reduction as
  `s1 + 2·s2 + 2·s3 + s4 + s5 − s6 − s7 − s8 − s9 (mod p)` over the sixteen 32-bit
  product words, then a bounded conditional add/subtract of `p`. Fewer folds, but
  **signed** intermediates — the borrows from the four subtracted `s_i` terms are
  the hazard, and the final `[0, p)` canonicalisation must be a masked (branch-free)
  select, not a data-dependent loop.

Either way `field.reduceWide` is the bit-exact oracle the differential pins to.

Inversion is Fermat (`a^(p−2)`) via a runtime square-and-multiply over the PUBLIC
exponent (constant-time in the secret element `a`). A short addition chain — the
one std's fiat inverse encodes — is the fast path a later phase can drop in;
inversion is amortised (one per affine conversion), so the scaffold favours obvious
correctness. Square roots use `a^((p+1)/4)` (valid because `p ≡ 3 (mod 4)`).

## Point representation & scalar multiplication

The curve is `y² = x³ − 3x + b` (`a = −3`). Points are **homogeneous projective**
`(X : Y : Z)` with the **Renes–Costello–Batina complete formulas specialised to
`a = −3`** — the SAME algorithms std uses: **Algorithm 6** for doubling (the a=−3
optimized double), **Algorithm 4** for addition. The formula bodies are mirrored
verbatim from `std.crypto.ecc.P256` and run over p256's `Fe`, so the whole group is
byte-exact vs std at the point level. P-256 has prime order (cofactor 1), so these
formulas are complete for all inputs (identity, equal points, inverses) — which is
what lets the constant-time ladder run with no special cases.

Scalar multiply variants (**NO GLV** — see below):

- **`mul`** — CONSTANT-TIME variable-base multiply (secret scalars: key
  derivation). Scaffold: fixed 256-bit double-and-add with a branch-free `cMov`
  bit select. Gated fast core: `mulCtWindowed`.
- **`combMulBase`** — CONSTANT-TIME fixed-base `s·G` (the ECDSA signing path:
  nonce commitment `k·G` + pubkey `d·G`). Scaffold: falls back to the double-and-add
  ladder over `G`. Gated fast core: `combMulBaseFast` (fixed-base comb).
- **`mulPublic` / `mulDoubleBasePublic`** — VARIABLE-TIME public-scalar multiplies
  (verification's `u1·G + u2·Q`). Plain double-and-add in this scaffold; a wNAF
  `slide` acceleration is owner-phase work (backlog).

### No GLV — the biggest structural difference from k256

secp256k1 admits an efficiently-computable endomorphism `φ(x,y) = (β·x, y)` acting
as `·λ`, which k256 exploits (balanced `k = k1 + k2·λ` split, half-length combine).
**P-256 admits no such endomorphism.** So there is no `splitScalar`, no lattice
basis, no half-length combine here — variable-base multiplies are plain windowed
forms and the fixed-base `k·G` uses a comb. This makes the *scalarmul* Fable core
simpler than k256's GLV, but the comb's **constant-time masked table scan** is the
same lesson and the same hazard.

### The comb / windowed CT masked-scan contract (for the Fable author)

The gated `combMulBaseFast` and `mulCtWindowed` run on SECRET scalars, so their
table gather MUST be a **masked linear scan** over every table entry at FIXED
offsets, with the per-entry select mask laundered through a `blackBox` inline-asm
barrier — so LLVM cannot recover "pick entry j == digit" and lower it to a
secret-indexed jump table (`jmp *tbl(,%reg,8)`), the powMont-gather leak class
(montint `b199192`, relived in the k256 comb). The signed-digit recoding must be
branch-free (`setcc`/`cmov`/masks, no `Jcc` on the scalar), and the conditional
point negation a masked field-negate. The comb table is built at **comptime** via
the portable field path (the `@inComptime()` guard in `field.zig` keeps the runtime
asm core out of the comptime interpreter) and stored **projective** (no comptime
inversions). Disassembly of the ReleaseFast `k·G` should confirm zero indirect
jumps and zero secret-indexed loads before the core is declared done.

## Constant-time contract

- **Field**: `mul`/`sq`/`add`/`sub`/`neg`/`invert` have a fixed operation schedule
  independent of the element value; the reduce/normalise is a masked conditional
  subtract (no branch, no secret-dependent memory access, the 0/1 carry bits
  laundered through `blackBox`). `invert`'s schedule depends only on the fixed
  public exponent.
- **Group**: `mul` (secret scalars) and `combMulBase` are constant-time; the
  fallback `mulDoubleAddCt` is a fixed 256-iteration double-and-add with `cMov`.
  `mulPublic`/`mulDoubleBasePublic` are explicitly VARIABLE-TIME and only for
  PUBLIC scalars (verification), matching std's contract.
- **Scalar**: inherited from std (constant-time fiat field), re-exported.
- **Gated cores** carry the same contract: the `MULX/ADX` field fold's trip count
  derives only from the public limb count; the comb/windowed gather must stay the
  `blackBox`-guarded masked scan.

The SCAFFOLD's portable path is the correctness reference, not a hardened
production target on its own; hardware side-channel review (esp. of the eventual
addition-chain inverse and the comb gather) is a later-phase obligation.

## Scope — the scalar field is intentionally std's

p256 accelerates the **field** and the **point multiply** (the ~hundreds of
base-field multiplies per scalar multiply). Scalar-field arithmetic mod `n` is a
handful of ops per signature — negligible against the point multiply — and `n` has
no exploitable special form. So `scalar.zig` re-exports std's constant-time scalar
field verbatim, keeping the complexity budget where the cost is. Unlike k256 there
are no GLV constants to own here.

## Verification

- **Field/group differentials** (`field.zig`/`group.zig`): `p256.op == std.op`
  byte-exact via `toBytes` on thousands of random inputs — mul/sq/add/sub/neg/
  invert/sqrt, dbl/add/scalarmul/comb/double-base, recoverY, SEC1 round-trip. This
  std differential is the anti-self-consistency anchor: std is a correct P-256 on
  the same curve, a far stronger oracle than self-consistency. Plus a reduction
  fold-boundary/max-limb edge sweep.
- **RFC 6979 official vectors** (`kat_vectors.zig`/`kat_test.zig`): the two P-256/
  SHA-256 rows (`"sample"`, `"test"`) from RFC 6979 A.2.5 must `ecdsaVerify` TRUE
  and tamper FALSE; std's own P-256 verifier is asserted to accept the same rows
  (pinning the transcription to std, not just to p256's self-consistency). This is
  the end-to-end anchor across an entirely independent (deterministic RFC 6979)
  implementation.
- **ECDSA differential** (`oracle_test.zig`): `sign.ecdsaVerify` accepts every
  signature from `std.crypto.sign.ecdsa.EcdsaP256Sha256` and rejects tampered ones;
  and every signature `sign.ecdsaSign` produces (random key + nonce) is accepted by
  BOTH p256 and std — sign+verify agree with std in both directions.
- **Broken positive control** (`kat_test.zig`): a Solinas fold with the wrong
  constant `M − 1` disagrees with std on >400/500 random inputs — proving the
  reduction constant is load-bearing and the equality checks have teeth.
- **Gated differentials** (`oracle_test.zig`): SKIP in this scaffold (both gates
  `false`); when a gate flips they pin the core bit-for-bit to the portable path.

## Performance status — SCAFFOLD baseline (portable oracle, the "before")

Both accelerators are gated OFF, so the numbers below are the **portable oracle**,
which — unlike k256, whose tiny-constant Solinas beat std's field — is **slower
than std** across the board (the 11-fold wide `M`-multiply reduction and the naive
double-and-add ladder are correctness-first, not fast). This host, ReleaseFast:

| op | p256-PORT | std | note |
|---|---|---|---|
| field mul | ~139 ns | ~61 ns | wide `M`-fold, 11 iterations |
| field sq | ~277 ns | ~112 ns | uses the general mul (no dedicated square yet) |
| CT `k·G` | ~1113 µs | ~323 µs | naive double-and-add vs std's windowed |
| ECDSA verify | ~1262 µs | ~756 µs | double-and-add double-base |
| ECDSA sign | ~1197 µs | ~405 µs | naive `k·G` + Fermat inverse |

The entire speedup lives in the two gated cores: the `MULX/ADX` field mul+square
(the dominant win — every point op is field-mul-bound) and the comb/windowed
scalar multiplies. Reaching the **~2–3× nistz256** target
(≈ 25 µs sign / ≈ 79 µs verify reference) is the Fable core phase + owner-verify
work, exactly as `k256` went from a portable scaffold to ~2.5× libsecp256k1.

## Backlog (the Fable phase + beyond)

1. `fast_core.fieldMul`/`fieldSq` — the `MULX/ADX` field mul + square with the
   P-256 Solinas fold (watch the wide-`M` fold-carry propagation / the signed
   word-shuffle borrows; see `fast_core.zig` + the montint/k256 asm notes).
2. `group.combMulBaseFast` — the fixed-base comb for `k·G` (comptime table,
   signed-digit, `blackBox`-guarded CT gather) — the fast signing path.
3. `group.mulCtWindowed` — the CT windowed variable-base multiply (secret scalars).
4. wNAF `slide` acceleration for `mulPublic` / `mulDoubleBasePublic` (the verify
   path; std uses a width-5 `slide`).
5. Addition-chain field inverse + a dedicated `MULX/ADX` square (replace the
   general-mul square) once the field core lands.
6. Rewire the P-256 consumers (jwt ES256, ctap2pin, spake2plus, hpke/voprf/mls/jwe)
   from `std.crypto.ecc.P256` to p256.
7. Side-channel review of the CT paths (inverse, comb/windowed gather).

# k256 — design & threat model

Auditor/design reference. Module purpose + API live in `README.md`; meta tags
live in `src/root.zig`'s `pub const meta`. This file covers the design decisions,
the constant-time contract, and the two gated Fable cores.

## Dedup — why this module exists although std HAS secp256k1

std ships `std.crypto.ecc.Secp256k1`, so k256 is **not** a std-gap fill in the
usual sense. It is a deliberate **performance-specialized reimplementation**,
justified by two facts:

1. **Measured gap.** std's curve is portable pure-Zig (a fiat-crypto Montgomery
   field, no asm, no GLV in the constant-time path), which is ~9–14× slower than
   libsecp256k1. The 8 Bitcoin/Lightning modules in this repo all ride it, and we
   cannot patch std.
2. **The collection's thesis.** zig-libs exists so native Zig is usable INSTEAD
   of linking a C library. A secp256k1 that is within a small factor of
   libsecp256k1 — while staying zero-C/no-libc — is exactly that thesis applied to
   the most performance-sensitive curve in the repo.

The realistic target is **~2–4× libsecp256k1**, taking the consumers from
~9–14× → ~2–4×. Parity with decades-tuned asm-grade C is explicitly a non-goal.

## Field representation — four full 2^64 limbs

`Fe` stores the base-field value as **four full 2^64 little-endian limbs**
(`[4]u64`), always canonical (`< p`) between operations, NORMAL domain (not
Montgomery — the special reduction is used directly, as libsecp256k1 does for its
field).

libsecp256k1's *portable* field uses 5×52-bit limbs; k256 does not, and the
choice is deliberate. 5×52 leaves 12 spare bits per limb to defer carry
propagation **in portable C, which has no hardware add-with-carry** — that is its
whole reason for existing. k256's accelerated path is `MULX/ADX`, where each
instruction consumes/produces a full 64-bit word and `ADCX/ADOX` propagate carries
in hardware; there the spare-bit trick is pure overhead, and 4×64 is the right
substrate (a 4×4 limb product is 16 `MULX` across two carry chains). This is the
same call `montint`'s asm core made; its register/flag discipline
(`montint/src/asm_core.zig`: AT&T suffixes, `dec` preserves CF, `MULX` touches no
flag, fold OF before loop control) transfers directly to the field-fold rows.

### The special-prime (Solinas) reduction

`p = 2^256 − 2^32 − 977`, so `2^256 ≡ c (mod p)` with `c = 2^32 + 977`. A
256×256→512-bit product is reduced by folding the high half: repeatedly replace
`x` by `(x mod 2^256) + c·(x ≫ 256)`. Each fold shrinks the excess by ~223 bits,
so **four folds** provably reach `< 2^256` (bounds: `<2^290 → <2^257 → <2^256+c →
<2^256`), after which one constant-time masked conditional subtract of `p`
canonicalises. The SCAFFOLD implements this on wide (`u256`/`u512`) integers
(`field.reduceWide`) — representative of the fold structure, and the correctness
oracle. The gated `MULX/ADX` core (`fast_core.fieldMul`/`fieldSq`) performs the
SAME fold on explicit 64-bit limbs; **carry propagation in that fold is the
classic error-prone spot** — the fold's `c·(high)` addition into the low limbs can
carry, and the second/third fold's top word must be handled without a
data-dependent branch. The differential (`oracle_test.zig`) pins it bit-for-bit to
`reduceWide`.

Inversion is Fermat (`a^(p−2)`) via a runtime square-and-multiply over the PUBLIC
exponent (constant-time in the secret element `a`; the sq/mul schedule depends
only on the fixed exponent). A short addition chain (libsecp256k1 uses ~255 sq +
15 mul) is the fast path a later phase can drop in — inversion is amortised (one
per affine conversion), so the scaffold favours obvious correctness. Square roots
use `a^((p+1)/4)` (valid because `p ≡ 3 mod 4`), which is BIP340's `lift_x` root.

## Point representation & scalar multiplication

Points are **homogeneous projective** `(X : Y : Z)` with the **Renes–Costello–
Batina complete formulas** (eprint 2015/1060, algorithms 7 & 9) — the same
exception-free, branch-free law std uses. secp256k1 has prime order (cofactor 1),
so these formulas are complete for ALL inputs (identity, equal points, inverses);
that completeness is what lets the constant-time ladder run with no special cases.
The formula bodies are arithmetically identical to std's, run over k256's `Fe`, so
the whole group is byte-exact vs std at the point level.

> The Fable phase's fast path will typically move the accelerated scalarmuls to
> **Jacobian** coordinates (cheaper mixed-add for a wNAF/precomp table) — that is
> an implementation freedom of the gated cores. The differential compares the
> resulting affine point, so the coordinate system inside a core is not
> constrained, only the result.

Scalar multiply variants:

- **`mul`** — CONSTANT-TIME fixed 256-bit double-and-add with a branch-free `cMov`
  bit select. For secret scalars (key derivation, signing nonce). No
  secret-dependent branch, index, or early exit; the complete formulas make every
  step exception-free.
- **`mulPublic`** — VARIABLE-TIME single-base multiply for public scalars; the
  dispatch point for the gated GLV core. Portable fallback: plain vartime
  double-and-add.
- **`mulDoubleBasePublic`** — VARIABLE-TIME `s1·P1 + s2·P2`, the verifier's
  `s·G − e·P` workhorse (BIP340 verify + ECDSA verify).

The fast-path DESIGN the Fable phase targets: a comptime fixed-base wNAF table for
`G` (constant-time base-point mul), and GLV for variable-base — documented here so
the core author has the target shape.

### GLV endomorphism (constants + decomposition)

secp256k1 admits `φ(x, y) = (β·x, y)`, acting on the prime-order subgroup as `·λ`
(a cube root of 1 mod n). The balanced decomposition writes any `k` as
`k = k1 + k2·λ (mod n)` with `|k1|, |k2| ≈ √n` (~128-bit), halving a variable-base
multiply's doublings. The constants (matching std's `Endormorphism`, transcribed —
std's are private):

- `λ = 0x5363ad4c...` (37718080363155996902926221483475020450927657555482586988616620542887997980018)
- `β = 0x7ae96a2b...` (55594575648329892869085402983802832744385952214688224221778511981742606582254)
- lattice split multipliers `g1`, `g2` (rounded `2^384·b_i/n`) and `−b1`, `−b2`
  (mod n) — the exact integers in `scalar.zig`.

`scalar.splitScalar` (k256's own reimplementation of the rounded-lattice method)
is REAL and tested byte-exact vs std's `Endormorphism.splitScalar` on 3000 random
scalars, plus a reconstruction check `k ≡ r1 + r2·λ`. The β/λ pair is independently
validated against the curve in `group.zig` (`φ(P) == λ·P`). The gated
`group.mulPublicGlv` consumes this proven decomposition; its remit is the `φ(p)`
map + the interleaved half-length wNAF combine, and (for the verifier) extending
GLV to the double-base `s·G − e·P` path.

## Constant-time contract

- **Field**: `mul`/`sq`/`add`/`sub`/`neg`/`invert` have a fixed operation schedule
  independent of the element value; the final reduce/normalise is a masked
  conditional subtract (no branch, no secret-dependent memory access). `invert`'s
  schedule depends only on the fixed public exponent.
- **Group**: `mul` (secret scalars) is fixed 256-iteration double-and-add with a
  `cMov` select — no branch on scalar bits. `mulPublic`/`mulDoubleBasePublic` are
  explicitly VARIABLE-TIME and only for PUBLIC scalars (verification), matching
  std's `mulPublic`/`mulDoubleBasePublic` contract.
- **Scalar**: inherited from std (constant-time fiat field), re-exported.
- **Gated cores** carry the same contract: the `MULX/ADX` field fold's trip counts
  derive only from the public limb count; the GLV core must keep the decomposition
  and combine free of secret-dependent branches (GLV in a constant-time context is
  the known-tricky part — sign handling of `k1`/`k2` must be masked, cf. std's
  `mulPublic` which is vartime and side-steps it).

The SCAFFOLD's portable path is the correctness reference, not a hardened
production target on its own; hardware side-channel review (esp. of the eventual
addition-chain inverse and the GLV sign handling) is a later-phase obligation.

## Scope — the scalar field is intentionally std's

k256 accelerates the **field** and the **point multiply** (the ~hundreds of
base-field multiplies per scalar multiply). Scalar-field arithmetic mod `n` is a
handful of ops per signature — negligible against the point multiply — and `n` has
no exploitable special form. Accelerating it would be effort with no measurable
payoff, so `scalar.zig` re-exports std's constant-time scalar field verbatim. This
keeps the module's complexity budget where the cost is, and keeps the scaffold
bounded. The GLV decomposition and the endomorphism constants ARE k256's own.

## Verification

- **Field/group/scalar differentials** (`field.zig`/`group.zig`/`scalar.zig`):
  `k256.op == std.op` byte-exact via `toBytes` on thousands of random inputs —
  mul/sq/add/sub/neg/invert/sqrt, dbl/add/scalarmul/double-base, recoverY, the GLV
  split, the β-endomorphism. This std differential is the anti-self-consistency
  anchor: std is a correct secp256k1 on the same curve, a far stronger oracle than
  self-consistency.
- **BIP340 official vectors** (`kat_vectors.zig`/`kat_test.zig`): the 8 secret-key
  rows sign byte-exact to the published signature; all 19 rows verify to the
  published TRUE/FALSE (catching R.y-parity, r/s-range, non-canonical-point). This
  is the end-to-end anchor across an entirely independent implementation.
- **ECDSA differential** (`oracle_test.zig`): `sign.ecdsaVerify` accepts every
  signature from `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256` and rejects tampered
  ones.
- **Recoverable ECDSA** (`ecdsa_recover.zig`'s own tests): RFC 6979 deterministic
  `sign` + `recoverPubkey` round-trip to the signer's own pubkey over random
  keys/messages, cross-checked against `sign.ecdsaVerify`; a bit-flipped signature
  recovers a DIFFERENT (or non-recoverable) key; the low-S boundary. Moved in from
  `lninvoice` (the original, and for a while only, consumer) — general secp256k1
  machinery, not anything BOLT#11-specific.
- **Broken positive control** (`kat_test.zig`): a Solinas fold with `c = 2^32 +
  976` (off by one) disagrees with std on >400/500 random inputs — proving the
  reduction constant is load-bearing and the equality checks have teeth.
- **Gated differentials** (`oracle_test.zig`): SKIP until each gate flips, then
  pin the core bit-for-bit to the portable path.

## Performance status — VERIFY and SIGN both optimized

All three accelerators are in and **both signature paths are optimized**.

**Verify** rides the `MULX/ADX` field multiply + the GLV double-base multiply:
ECDSA/BIP340 verify at **~2–3.5× libsecp256k1** (this host: field mul ~2.9×,
ECDSA verify ~2.5× libsecp / ~6.5× std).

**Sign** now rides the **fixed-base comb table** (`group.combMulBase`, backlog
#3): a precomputed table of `G`-multiples turns each secret `k·G` into a
constant-time table-gathered sum with NO online doublings. The base-point
multiply drops from **~208 µs → ~33 µs (~6.2×)** and BIP340/ECDSA sign from
**~395 µs → ~93 µs (~4.3×)** this host — i.e. from ~10× to **~2.3× libsecp256k1**
(vs the ~40 µs reference), inside the module's ~2–4× target. Sign stays byte-exact
to the 8 official BIP340 sign vectors, now through the comb path.

### The comb (constant-time k·G) and its side-channel contract

Window `w = 4`, `comb_t = 65` signed digits (a running-carry Booth recoding, so
`Σ dᵢ·2^{w·i} = k` exactly, incl. the raw-scalar range to 2^256−1). Each window
owns a table of `{1,…,2^{w−1}}·2^{w·i}·G`; the sign of a digit is a masked point
negation, halving the table. The table is **comptime-generated** via the portable
field path (an `@inComptime()` guard in `field.zig` keeps the runtime asm core out
of the comptime interpreter) and stored **projective** (no comptime inversions).
Memory: `65·8·(3×32 B) = 48.75 KiB` of `.rodata`.

Constant-time contract (secret nonce — verified by disassembly of the ReleaseFast
`k·G`):
- **Table gather is a masked linear scan** over every entry of each window, at
  FIXED table offsets, with the per-entry select mask laundered through a
  `blackBox` inline-asm barrier — so LLVM cannot recover the equality and lower it
  to a secret-indexed jump table (the powMont-gather leak class, montint
  `b199192`). Disasm confirms: zero indirect jumps, zero secret-indexed loads
  (the only base+index operand is the window extraction `k >> shift`, whose index
  is the PUBLIC loop counter).
- **The signed-digit recoding is branch-free** (`setcc`/`cmov`/masks, no Jcc on
  the scalar), and the conditional point negation is a masked field-negate.
- **The portable field `normalize`/`sub` selects are `blackBox`-laundered** too:
  without the barrier LLVM turned the `mask = 0 − carry` field-carry select into a
  data-dependent `test/jne` — a secret-dependent branch on the k·G path. After
  laundering, the only branches left on the whole path are the public-trip-count
  loop control and the standard final `rejectIdentity` endpoint check (reveals
  only "result == O", always false for a valid nonce, as in std's `basePoint.mul`).

## Backlog (the Fable phase + beyond)

1. ~~`fast_core.fieldMul`/`fieldSq` — the `MULX/ADX` field mul + square with the
   special-prime fold (watch the fold-carry propagation; see montint's asm notes).~~
   **DONE** — `gate.field_asm_implemented = true`; core-vs-portable differential
   live in `oracle_test.zig`.
2. ~~`group.mulPublicGlv` — GLV+wNAF variable-base multiply on the proven
   `splitScalar`; extend GLV to the double-base verify path.~~
   **DONE** — `gate.glv_scalarmul_implemented = true`; differential live.
3. ~~Fixed-base wNAF/precomp table for `G` (constant-time base-point mul).~~
   **DONE** — `group.combMulBase` (fixed-base comb, w=4, signed-digit,
   blackBox-guarded CT gather). Sign ~4.3× faster (~2.3× libsecp256k1).
4. Addition-chain field inverse (replace the Fermat square-and-multiply).
5. Rewire the 8 Bitcoin/Lightning modules from `std.crypto.ecc.Secp256k1` to k256.
6. Side-channel review of the CT paths (inverse, GLV sign handling).

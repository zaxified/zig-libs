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

### MEASURED, not merely asserted (ctgrind)

Every statement above used to rest on disassembly read once by hand. Since
2026-08-13 it rests on a committed program:
[`src/ctgrind_harness.zig`](src/ctgrind_harness.zig), run by
`scripts/ctgrind.sh k256`, which marks the secret `MAKE_MEM_UNDEFINED`, forces a
volatile reload, and drives it through five code paths.

**Full control table** (zig 0.16.0, valgrind 3.26.0, x86_64, ReleaseFast,
re-measured 2026-08-13 after the `ecdsa` target and the driver's fail-closed
counting rule were added). Three bucket columns, not one, and they sum to
`total` on every row:

- `in-file` — contexts whose stack names a k256 source file (see
  `scripts/ctgrind.sh`'s `PATTERN` map for the exact regex per target);
- `witness` — contexts in the harness's own result formatting, which is not
  constant-time on purpose: it is what proves the taint arrived;
- `unattr` — contexts matching NEITHER. **Always a `--check` failure.** Before
  this column existed the driver silently dropped them, and that is not
  hypothetical: see the `Fe.cMov` row of the positive-control table below.

| target | what is tainted | `-fvalgrind` | tainted | total | in-file | witness | unattr | exit |
|---|---|---|---|---|---|---|---|---|
| `field` | element + `cMov` select bit | yes | **yes** | 6 | **0** | 6 | 0 | 99 |
| `field` | — | yes | no | 0 | 0 | 0 | 0 | 0 *(control)* |
| `field` | — | **no** | yes | 0 | 0 | 0 | 0 | 0 *(trap)* |
| `mul` | scalar | yes | **yes** | 8 | **2** | 6 | 0 | 99 |
| `mul` | — | yes | no | 0 | 0 | 0 | 0 | 0 *(control)* |
| `mul` | — | **no** | yes | 0 | 0 | 0 | 0 | 0 *(trap)* |
| `comb` | scalar | yes | **yes** | 7 | **1** | 6 | 0 | 99 |
| `comb` | — | yes | no | 0 | 0 | 0 | 0 | 0 *(control)* |
| `comb` | — | **no** | yes | 0 | 0 | 0 | 0 | 0 *(trap)* |
| `sign` | 32-byte secret key | yes | **yes** | 13 | **11** | 2 | 0 | 99 |
| `sign` | — | yes | no | 0 | 0 | 0 | 0 | 0 *(control)* |
| `sign` | — | **no** | yes | 0 | 0 | 0 | 0 | 0 *(trap)* |
| `ecdsa` | 32-byte private key | yes | **yes** | 15 | **10** | 5 | 0 | 99 |
| `ecdsa` | — | yes | no | 0 | 0 | 0 | 0 | 0 *(control)* |
| `ecdsa` | — | **no** | yes | 0 | 0 | 0 | 0 | 0 *(trap)* |

**The field layer is zero.** `Fe.cMov` driven by a TAINTED select bit,
`add`/`sub`/`normalize`, the amd64 `fast_core` `mul`/`sq`, and `invert`'s
public-exponent `powConst` together report **0** contexts in `field.zig` /
`fast_core.zig`. That zero is readable only because the other three rows are
non-zero: the taint demonstrably propagates through this module's arithmetic.

**The 2 + 1 group contexts are `rejectIdentity`, not the ladder.** Located
exactly (`--stacks`):

- `group.zig:277` — `mul`'s trailing `try q.rejectIdentity()` (2 contexts: LLVM
  splits the `z = 0` test from the affine-identity test);
- `group.zig:346` — `combMulBaseWithTable`'s `try acc.rejectIdentity()`.

Both branch on "did the whole multiplication land on the neutral element", i.e.
`s ≡ 0 (mod n)` — one bit, once, after the ladder, not per scalar bit or per
window. It is the same validation `std.crypto.ecc.Secp256k1.mul` performs and it
is what makes `error.IdentityElement` reachable. **The per-bit `cMov` select and
the per-window masked table gather report nothing**, which is the claim the
`blackBox` barriers exist to hold.

**The 11 `sign` contexts** are **two at `group.zig:346`** — one per
`combMulBase` call, inlined from `sign.zig:62` and `sign.zig:80` — plus nine
input/output validations, all on lines that must branch by contract:

- `sign.zig:58` / `:76` — `dp.isZero()` / `k0.isZero()`, the BIP340-mandated
  "fail if d′ = 0 / k′ = 0" checks;
- `sign.zig:64` / `:83` — `Pa.y.isOdd()` / `Ra.y.isOdd()`, branches on the
  PUBLIC key and the PUBLIC nonce point (memcheck has no notion of "public
  function of a secret", so tainting `sk` taints them too);
- five contexts at std's `crypto/pcurves/common.zig:75` — `Field.fromBytes`'s
  canonicality rejection, reached from `scalar.zig:87`/`:202`/`:208`. That is
  std's own scalar field, which `scalar.zig` re-exports verbatim (see "Scope"
  below); k256 adds no branch there.

(An earlier revision of this paragraph said the `sign` row's two group contexts
were "those two" from the bullets above — i.e. `mul`'s `group.zig:277` and
`comb`'s `group.zig:346`. Measured: `bip340Sign` never calls `Secp256k1.mul`,
so `group.zig:277` appears in the `mul` row only, and `sign`'s pair is
`group.zig:346` twice. The count was right; the attribution was not.)

**The 10 `ecdsa` contexts** — `ecdsa_recover.sign`, RFC 6979 deterministic
ECDSA, the module's other shipped secret path (in-repo consumer: `lninvoice`'s
BOLT#11 signer). One is `group.zig:346` again; the rest are validations, with
one exception that is called out because it is genuinely a branch on secret
material:

- `ecdsa_recover.zig:126` (via `scalar.zig:87`) / `:127` — canonicality and
  `isZero` on the caller's private key;
- `ecdsa_recover.zig:105` (via `scalar.zig:87`) — canonicality of the DRBG
  output, inside `rfc6979Nonce`;
- **`ecdsa_recover.zig:106` — `if (!cand.isZero())`, the RFC 6979 §3.2 retry
  test, a branch on the SECRET nonce candidate.** Retry probability ≈ 2^-127
  (the rejected set `[n, 2^256) ∪ {0}` has size < 2^129 out of 2^256); kept
  because there is no rejection-free variant that still yields the RFC's exact
  nonce, and libsecp256k1's `nonce_function_rfc6979` branches on the same
  condition. Documented at the source, not silenced;
- `group.zig:346` — `combMulBaseWithTable`'s `rejectIdentity` on `k·G`;
- `ecdsa_recover.zig:133` (via `scalar.zig:87`) / `:134` — canonicality and
  `isZero` on `r`;
- `ecdsa_recover.zig:136` — `s.isZero()`;
- `ecdsa_recover.zig:143` — `Ra.x.toInt() >= n`, the recid bit-1 case;
- `ecdsa_recover.zig:152` — `isLowS(s)`, the BIP-62 canonicalisation.

`recoverPubkey` is deliberately unmeasured: every one of its inputs is public,
and it ends in the variable-time `mulDoubleBasePublic`.

**The harnesses were shown to have teeth** (positive controls, each reverted and
`cmp`-verified byte-identical afterwards):

| injected defect | effect |
|---|---|
| `blackBox` removed from `Fe.cMov` | `--check` **FAILS**. On the `field` row the leak appears as **1 unattributed** `Conditional jump` context (total 6 → 5, in-file still 0), stack `reloadVolatile (ctgrind_harness.zig:0)` ← `main` — memcheck attributes the inlined select to the harness file, so no k256 pattern matches it. `mul` 8/2 → 1/1, `comb` 7/1 → 8/2, `sign` 13/11 → 17/15. **Until 2026-08-13 the field row read 0/0 and the driver dropped that context silently**; that is why `unattr` exists (`scripts/ctgrind.sh`, "the SECOND trap"). |
| `blackBox` removed from `normalize`'s three masks AND `Fe.sub`'s, `Fe.cMov`'s kept | `mul` 8/2 → **35/29**: 28 NEW contexts, all at `normalize (field.zig:83)` and `normalize (field.zig:91)` — the carry fold and the conditional subtract, branching on the secret. `normalize`'s barriers are load-bearing and this is the measurement that shows it. (Removing ALL barriers *including* `Fe.cMov`'s does NOT show this: the `cMov` leak resolves the taint first and these contexts never appear, which is the same "total can go down" effect noted below. A whole-file barrier kill is the WRONG control for a per-site question.) |
| `blackBox` removed from `Fe.sub`'s mask ALONE | `mul` 8/2 → 7/1 and **no new context at `field.zig:229`/`:230`** — the count moved DOWN. `Fe.sub`'s barrier has **no demonstrated teeth** under this harness. It is kept as defence-in-depth against a compiler that would lower the masked add-back to a branch, not because one currently does; nothing here proves it is preventing anything. |
| `q.cMov(added, bit)` → `if (bit == 1) q = added` | new context at `group.zig:275` |
| masked comb gather → `g = tab[i][m-1]` | `comb` 1 → 4 contexts, including memcheck's "Use of uninitialised value of size 8" on the *address* — the b199192 secret-indexed-load signature |
| branch on a byte of the secret scalar `d` in `bip340Sign` | `sign` 11 → 12, new context at the injected line |
| `rfc6979Nonce` → constant `0x42`×32 | `zig build test-k256` **exit 1**, one failure: the BOLT#11 nonce anchor in `ecdsa_recover.zig`. Before that test existed (2026-08-13) the same mutation left all 34 tests green at **exit 0**, with the only red in the repository being the CONSUMER `lninvoice`. |

Note for anyone re-running these: an injected leak can make the TOTAL go **down**
(memcheck resolves the branch and the taint stops propagating downstream), so
"the number went up" is the wrong pass criterion. The criterion is "a new context
appeared at the mutated location".

**What is deliberately NOT measured**: `mulPublic` / `mulPublicGlv` /
`mulDoubleBasePublic` and everything under them are documented VARIABLE-TIME for
PUBLIC scalars. Tainting a scalar into them would light up memcheck by design and
would measure nothing about a claim.

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
- **The deterministic nonce's own anchor** (`ecdsa_recover.zig`, added
  2026-08-13): BOLT#11's first worked example — the specification's own private
  key, its own signing-preimage SHA-256, and the `(r, s, recid)` carried by the
  `lnbc1pvjluez…` string it prints — must be reproduced byte-exact, and the same
  private key must produce the node ID the spec prints. Note what this fixes:
  every OTHER test here is self-consistent under any nonce, so replacing
  `rfc6979Nonce` with a constant left all 34 tests green (exit 0) and reddened
  only the CONSUMER `lninvoice`. It now reddens this module. **This is a BOLT#11
  artifact, not an RFC 6979 one** — RFC 6979 Appendix A.2 publishes vectors for
  DSA and the NIST curves only (A.2.5, P-256, is what `p256` transcribes); it
  has no secp256k1 section.
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
  data-dependent `test/jne` — a secret-dependent branch on the secret-scalar path.
  For `normalize` this is now measured, not just disassembled: removing its three
  barriers (and leaving `Fe.cMov`'s in place) puts **28 new memcheck contexts** at
  `field.zig:83`/`:91` in the `mul` row. For **`Fe.sub`'s single barrier there is
  no such measurement**: removing it alone produces no new context anywhere, so it
  stands as defence-in-depth, not as a barrier shown to be holding a branch back
  today. After laundering, the only branches left on the whole path are the
  public-trip-count loop control and the standard final `rejectIdentity` endpoint
  check (reveals only "result == O", always false for a valid nonce, as in std's
  `basePoint.mul`).

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

## Anchoring

**Anchor grade:** class B · oracle EXTERNAL

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** official BIP340 vectors (kat_vectors.zig) + bit-exact vs std.crypto.ecc.Secp256k1

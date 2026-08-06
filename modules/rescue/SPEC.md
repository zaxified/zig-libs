# rescue — design, sources & divergences (SPEC)

Auditor/design reference. Consumer usage lives in `README.md`; metadata lives
in `src/root.zig`'s `pub const meta`; this file does not restate either.

## What was actually decided

Four decisions carry the module. Everything else follows.

| decision | choice | why |
|---|---|---|
| which variant | **RPO**, not paper Rescue-Prime | it is the one with a deployed implementation *and* published vectors |
| which field | **Goldilocks**, implemented in-module | RPO is specified over it and nothing else; no field module here is 64-bit |
| which sponge | **both** framings that exist | they disagree on every digest and both are real |
| constants | **derived** from SHAKE256, pinned against a deployed table | puts the rule in the repo, not the output |

## Sources

Consulted in this order:

1. **The Rescue paper** — *Design of Symmetric-Key Primitives for Advanced
   Cryptographic Protocols*, Aly/Ashur/Ben-Sasson/Dhooghe/Szepieniec,
   <https://eprint.iacr.org/2019/426>. The design strategy; no usable
   parameters.
2. **The Rescue-Prime specification** — *Rescue-Prime: a Standard
   Specification (SoK)*, Szepieniec/Ashur/Dhooghe,
   <https://eprint.iacr.org/2020/1143>. Defines Rescue-XLIX (Algorithm 3) and
   the constant generator (Algorithm 5). Reference implementation:
   `git clone https://github.com/KULeuven-COSIC/Marvellous` (`b265d9a`),
   `rescue_prime.sage` — SHA-256
   `3026f9e82332f828062c516a273ab60f3bca10bc22085c64647c6f09d96ede12`.
   **Publishes no test vectors.**
3. **Rescue-Prime Optimized** — Ashur/Al Kindi/Meier/Szepieniec/Threadbare,
   <https://eprint.iacr.org/2022/1577>.
   `git clone https://github.com/ASDiscreteMathematics/rpo` (`b2889d6`):
   `reference_implementation/rescue_prime_optimized.sage`
   (`d8fadb13f4fb2cd6b31c7b3eb0fae22a2062546370ecdaaffa61e8f61ec7e69b`) and
   `report/report.tex`
   (`3967df818957da5096883cccd8ca2d82125a825f0be6f81aba4d9c4228b5b837`),
   whose §"Test Vectors" carries 19 + 19 published digests.
4. **The deployed implementation** — `git clone
   https://github.com/0xPolygonMiden/crypto` (`475092a`),
   `miden-crypto/src/hash/algebraic_sponge/rescue/{mod.rs,rpo/{mod.rs,tests.rs}}`.
5. **A second implementation, of the *paper* variant** — `git clone
   https://github.com/facebook/winterfell` (`2f78ee9`),
   `crypto/src/hash/rescue/rp64_256/{mod.rs,tests.rs}`.

Per-file SHA-256s for everything the tests consume are listed in
`src/upstream_vectors.zig`, alongside the extraction command for each table.

## Divergences

### 1. Rescue-Prime vs RPO — followed: RPO, with the paper's round order shipped alongside

They are not variants of one function. The round differs:

```text
Rescue-Prime (2020/1143 Alg. 3):  S-box     -> MDS -> +ARK1 ; S-box^-1 -> MDS -> +ARK2
RPO          (2022/1577):         MDS -> +ARK1 -> S-box     ; MDS -> +ARK2 -> S-box^-1
```

and so do the MDS (RPO fixes a circulant matrix; the paper *generates* one from
the echelon form of a Vandermonde matrix) and the constant seed string
(`"RPO(...)"` vs `"Rescue-XLIX(...)"`).

**RPO wins on anchoring, which is the only criterion that could settle it.**
The paper variant publishes no test vectors at all — the Marvellous reference
has no `print_test_vectors` — while RPO publishes 38 and has an implementation
whose digests are load-bearing for a live system. A paper-variant module would
have been grade 3 wearing a grade 1 name.

The paper's round order still ships, as `xlix.zig`, permutation-only, anchored
on Winterfell's published KAT. It exists so the divergence is executable: same
field, same `alpha`, same circulant MDS row, and
`xlix.permute([0..11]) != rpo.permute([0..11])` in all twelve positions
(asserted).

### 2. Two RPO sponges — followed: both

The RPO report and miden-crypto disagree about how to wrap the permutation:

| | reference sage | miden-crypto |
|---|---|---|
| capacity | `state[0 .. c]` | `state[8 .. 12]` |
| rate | `state[c .. m]` | `state[0 .. 8]` |
| digest | `state[c .. c + r/2]` | `state[0 .. 4]` |
| padding | `input ++ [1] ++ 0*`, only when `len % r != 0` | zeros |
| domain separation | `state[0] = 1` when padded | `state[8] = len mod r`, always |
| byte hashing | not defined | 7-byte chunks, flag `= r + (n mod r)` |
| empty input | rejected (`error.EmptyInput`) | zero digest, no permutation |
| widths | `m = 12` and `m = 16` | `m = 12` |

miden-crypto's padding rule is deliberate and cited — it follows
<https://eprint.iacr.org/2023/1045> §"padding", not the RPO report. So there is
no "wrong" one to drop: the report's framing is what the specification's own
vectors exercise, and miden's is what a Miden VM digest actually is. Shipping
one would have meant discarding 19 published vectors or the only deployed
consumer. `vectors_test.zig` additionally asserts the two never agree, so a
future refactor cannot quietly merge them.

### 3. miden-crypto changed its state layout — followed: the current one

miden-crypto PR #755 (listed `[BREAKING]` in its CHANGELOG) moved the sponge
state from `[CAPACITY, RATE1, RATE0]` to `[RATE0, RATE1, CAPACITY]`. The
permutation is untouched — same ARK, same MDS — but the framing indices moved,
so **every digest changed**. Anything holding pre-#755 Miden digests is holding
values this module will not reproduce.

How to tell which corpus you have, with no code: `Rpo256::hash_elements([0])`
is `8563248028282119176, …` under the current layout. If your corpus disagrees
on that, it predates #755, and the fix is a rate/capacity remap in the framing —
not a different permutation.

This module implements the **current** layout, because that is what
miden-crypto's own test vectors assert and what the Miden VM runs today.

### 4. The constants I could not re-derive

Winterfell's `Rp64_256` comments its round constants as "computed using
algorithm 5 from eprint 2020/1143" — the same SHAKE256 generator this module
already implements. **They do not reproduce.** Tried and rejected: seed
templates `Rescue-XLIX(p,m,c,s)`, `Rescue-Prime(p,m,c,s)` and `RPO(p,m,c,s)`;
`capacity ∈ {4, 6, 8}`; `security_level ∈ {80, 128, 160}`; `bytes_per_int ∈
{8, 9, 10}`; both byte orders; and a scan for `ARK1[0][0]` anywhere in the first
576 constants of every resulting stream. No hit.

So `xlix_constants.zig` is **embedded, not derived** — the one table in this
module that is a blob. It is pinned by the SHA-256 of the upstream file it came
from and, more usefully, by Winterfell's own published permutation KAT, which
would fail on a single wrong constant. This is stated rather than papered over:
if someone recovers the generator invocation, that table should become derived
and this section should shrink to a footnote.

(The same generator *does* reproduce miden's RPO tables exactly, all 168 values,
which is what makes the RPO half of this module grade 1 at the constant level.)

### 5. Not shipped

* **RPX** (`eprint 2023/1045`) — Rescue-Prime eXtended, which miden-crypto also
  ships. Different round structure (three round types), different constants,
  its own vectors. A separate follow-up, not a flag on this one.
* **A sponge for `xlix`.** Winterfell's `Rp64_256` hasher exists (additive
  absorption, capacity at `0..4`, `state[0] = num_elements`) but publishes no
  digest KAT — only the permutation one. Building it would mean shipping a
  grade-3 framing inside a grade-1 module.
* **Rescue over BN254 / BLS12-381.** No published parameters, no vectors, no
  consumer. Would be an unanchored guess wearing the name.
* **Circuit / constraint-system integration.** Out of scope; the whole point of
  Rescue is what a constraint system does with it, and that belongs in whatever
  `groth16`-side gadget wants it.

## The Goldilocks field is in-module on purpose

`goldilocks.zig` is ~240 lines of code (plus its own differential tests) and is
**not** a general-purpose field module — by decision, not by neglect:

* RPO is specified over `p = 2^64 - 2^32 + 1` and nothing else — the reference
  sage hard-codes it in five places. There is no parameterisation to expose.
* The repo's existing scalar fields (`bn254`, `bls12_381`) are 254/255-bit and
  cannot host it; `montint` targets large odd moduli with Montgomery form,
  which a Solinas 64-bit prime does not want.
* One consumer. `meta.deps` is empty and a test asserts it. If a second
  consumer appears — a Goldilocks STARK, a Poseidon2-over-Goldilocks — that is
  the moment to extract it, and the extraction is mechanical.

Representation is **canonical** (`[0, p)`), not the redundant `[0, 2^64)` that
plonky2 and Winterfell use. Canonical costs one masked subtraction per
operation and buys trivial equality, trivial serialisation and no
"canonicalise before comparing" footgun. That is the right trade for a hash
whose cost is dominated by the S-box anyway.

## Constant time

**Yes, throughout, and it is meant to stay that way.**

* The field is branch-free: `condSub`, `add`, `sub` and `reduce128` build
  masks from `@intFromBool` comparisons and never branch or index on a value.
  On x86-64 this is `cmp`/`setae`/`neg`/`and`, verified by reading the emitted
  code for `mul` (no `Jcc` on data; one `cmovae` from the compiler's own
  selection, which is also data-independent in timing).
* **The inverse S-box is not a variable-time ladder.** It is a fixed
  72-multiplication addition chain — the same sequence for every input, no
  bits inspected, no early exit. This is worth saying explicitly because the
  obvious implementation of `x^(1/alpha)` *is* a square-and-multiply over a
  64-bit exponent, and a naive one would be data-independent only by accident
  (the exponent is public, so even a windowed ladder would be safe here — but
  the chain removes the question, and it is measurably faster: 0.290 µs vs
  0.358 µs for the module's own constant-time 64-iteration ladder, 1.23x).
* `pow` is a fixed 64-iteration masked ladder. It is used by tests and by the
  comptime MDS inversion, never on the hot path.
* The permutation and both sponges have fixed loop bounds over public lengths.
  The only length-dependent control flow is "how many blocks to absorb", which
  is a function of the *public* input length.

**Does it matter?** For the dominant use — hashing public circuit data — no.
It matters for the three cases this module is expected to serve, which is why
the property is worth having rather than disclaiming: Merkle *membership*
proofs where the leaf and path are secret; commitments to witness values; and
Fiat-Shamir transcripts absorbing secret intermediates.

**Caveat, stated rather than left open:** unlike `k256` and `montint`, this
module has **not** been CT-verified in a full disassembly sweep. The claim
rests on the source shape, a spot check of `mul`, and the absence of any
data-dependent branch or table index in the sources.

## Performance notes

Numbers are in `README.md`. Two things worth an auditor's attention:

**The S-box layer shape is load-bearing, not cosmetic.** Written the obvious
way — `for (state) |*s| s.* = sboxInv(s.*)` — the 72-multiply body is far past
LLVM's unroll threshold, so the `m` chains run strictly one after another and
the layer costs `m` × 72 *latencies*. Advancing all `m` lanes one chain step at
a time is the same instruction count with `m`-way ILP: measured
**48.0 µs → 27.4 µs** per permutation. Rewriting the field's carry handling from
`@addWithOverflow` tuples (which LLVM was spilling to stack) to explicit
comparison masks took it to **18.15 µs**. Every RPO implementation is written
lane-parallel; this is why.

**Left on the table**, deliberately: the AVX2/AVX-512 paths miden-crypto ships,
and the non-canonical `[0, 2^64)` representation that would drop one masked
subtraction per operation. Both are real and both are unmeasured here — no
head-to-head against miden's scalar or SIMD paths was run, so this module makes
no claim about how it compares. Neither is worth the complexity until something
in this repo actually hashes at volume with Rescue; if that happens, the honest
first move is SIMD, not micro-tuning the scalar reduce.

**Not marked `heavy`** in `build.zig`: strict-Debug compile ~8.5 s + run ~1.0 s
= 9.5 s, under the >15 s threshold — and a ReleaseSafe compile of this module
is ~46 s (comptime SHAKE256 + heavily unrolled field code), so marking it heavy
would cost 5x what it saves. There is no parameter sweep to gate: RPO defines
exactly two instances and both are always tested.

**Constants are derived at comptime** (~1.4 s of the compile), unlike
`poseidon`, whose Grain LFSR had to stay at run time. Keccak is cheap in the
Zig interpreter; a 1512-byte squeeze is 12 permutations.

## Anchoring summary

Grade 1 for the permutation, both framings' element paths and the constants;
grade 2 where no published vector exists to have. Nothing rests on grade 3.

| claim | grade | rests on |
|---|---|---|
| RPO permutation, `m = 12` | 1 | 19 report vectors + 19 miden vectors |
| RPO permutation, `m = 16` | 1 | 19 report vectors |
| `spec128` / `spec160` framing | 1 | the report's vectors |
| `Rpo256` framing (elements, merge) | 1 | miden-crypto's `EXPECTED` |
| `Rpo256.hash` (bytes) | 2 | **no upstream byte-input KAT exists** (checked: miden's suite has only inequality properties). Instead its `hash_padding_no_extra_permutation_call` test is ported — the expected digest is built from the *permutation*, which is grade 1, plus the packing rule read from miden's source — and its `hash_padding` inequality cases are reproduced verbatim |
| RPO round constants | 1 | element-wise vs miden's embedded ARK1/ARK2 |
| 160-bit round constants | 2 | SHA-256 pin from an independent Python port of the sage generator; transitively grade 1 via the report vectors |
| `alpha`, `1/alpha` | 1 | computed by extended Euclid, checked against the value both deployed implementations publish |
| Rescue-XLIX permutation | 1 | Winterfell's published KAT |
| Rescue-XLIX constants | — | embedded blob, pinned by upstream file digest; see divergence 4 |
| Goldilocks arithmetic | 2 | differential vs a `u128 % p` oracle (40 k fixed + fuzzed) |

Nothing here is grade 3. The weakest links are named above and in the
divergences: the byte path (no upstream KAT exists to have) and the
Rescue-XLIX constant blob (no derivation recovered).

## Backlog

* Recover Winterfell's constant-generation invocation and turn
  `xlix_constants.zig` into a derivation (divergence 4).
* RPX, if a consumer appears.
* A CT disassembly sweep, to bring this module up to `k256`/`montint`'s
  standard of evidence rather than argument.
* SIMD S-box layers, if Rescue ever lands on a hot path here.

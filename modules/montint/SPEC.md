# montint — design & threat model (SPEC)

Auditor/design reference. Consumer usage lives in `README.md`; metadata lives
in `src/root.zig`'s `pub const meta`; this file does not restate either.

## What this module is

A constant-time **Montgomery** big-integer modular-arithmetic type,
`Modint(max_bits)`, over **arbitrary ODD moduli** — prime OR composite. It is
the API analogue of `std.crypto.ff.Modulus` (`toMontgomery`/`fromMontgomery`,
modular `add`/`sub`/`mul`, constant-time modexp) built to *beat* it on amd64.
Because it must accept composite moduli (RSA/Paillier `N`, a hidden-order VDF
group) it is deliberately **not** called a "field" — there is no inversion by
Fermat, no primality assumption.

## Why it exists (std-gap, not a dup)

The deep audit (`~/CML/audit/modules/{rsa,paillier,vdf}.md`) measured every
bignum-crypto module in this repo — all backed by `std.crypto.ff` — at ~8–29×
OpenSSL:

| module | op | this host | vs OpenSSL |
|---|---|---|---|
| rsa | 2048 CRT sign | 19.33 ms | 28.9× |
| rsa | 2048 verify | 180 µs | 8.2× |
| paillier | 4096 decrypt | 135 ms | ~27× |
| vdf | 2048 squaring | 21 µs | ~7–10× |

The root cause is structural, traced in `ff.zig`: it stores **63-bit redundant
limbs** (`carry_bits = 1`, `t_bits = 63`) and multiplies limbs via a 4-way
half-limb `mulWide` (`ff.zig:907`). That representation *cannot* use the host's
add-with-carry (`ADCX/ADOX`) or widening multiply (`MULX`) — the exact
instructions OpenSSL's `x86_64-mont5.pl` is built on. We cannot patch std, and
this is not something the other modules can fix locally.

`montint` is the fix once, shared: **full radix-2^64 limbs**, so the amd64
`MULX/ADCX/ADOX` dual-carry-chain Montgomery multiply drops in. It is a genuine
new capability (asm-accelerated modmul on full limbs), not a re-implementation
of an existing module — `bfv`'s `modarith` is single-word NTT-prime arithmetic,
a different regime (see its SPEC's reuse map).

## Representation

- Values are `[L]u64`, little-endian, `L = ceil(max_bits/64)` **full 2^64
  limbs** (no reserved carry bit). The modulus occupies exactly `L` limbs
  (leading zero limbs allowed; only oddness and `≥ 3` are required).
- Montgomery domain: `R = 2^(64·L)`. `toMontgomery(a) = a·R mod m`,
  `fromMontgomery = ·R⁻¹`. Values stay Montgomery-resident across a modexp;
  convert only at the boundary.
- Setup constants: `n0inv = -m[0]⁻¹ mod 2^64` (Newton–Hensel, 6 doublings);
  `one_mont = R mod m` and `r2 = R² mod m` via repeated CT doubling mod m
  (128·L doublings — obviously correct, once, at construction).

## Algorithms

- **Montgomery multiply — CIOS** (Coarsely Integrated Operand Scanning, Koç et
  al. *Analyzing and Comparing Montgomery Multiplication Algorithms*, Fig. 6),
  radix 2^64, `u128` widening products, single accumulator of `L+2` words,
  final constant-time conditional subtract. This is the portable ORACLE
  (`montMulCios`) and the shape the asm core mirrors instruction-for-instruction
  with two independent carry chains.
- **Modexp — fixed 5-bit window, constant-time.** Precompute `table[k] = x^k`
  (k = 0..31) in the Montgomery domain; process ALL `L·64` exponent bits MSB→LSB
  in 5-bit windows: 5 squarings + one multiply per window, digit 0 multiplies by
  `1` (so the multiply is unconditional), table gather is a branchless
  `select` over all 32 entries. This is the analogue of `ff`'s secret path and
  the guarantee `rsa`/`paillier` need.
- **Karatsuba / large sizes (`limbs.zig`).** Full radix-2^64 schoolbook and a
  single-level Karatsuba full-product are shipped and mutually cross-checked
  (they are each other's anchor). CIOS itself is O(n²) interleaved — matching
  OpenSSL `mont5`, whose 2048/4096 win is `MULX/ADX`, **not** Karatsuba — so the
  Karatsuba/schoolbook pair is the building block for the **deferred** large-size
  SOS path (separate full multiply, then a Montgomery reduce), not wired into
  the modmul yet. The threshold (`karatsuba_threshold = 16`) is descriptive; the
  tuned crossover is a bench-time question.

## The asm core (implemented — was the scaffold cut-line)

Exactly one function was gated (`gate.asm_core_implemented`, now `true`):

```
asm_core.montMul(z: []u64, a, b, m: []const u64, n0inv: u64)   // z = a·b·R⁻¹ mod m
```

the hand-written x86-64 `MULX/ADCX/ADOX` CIOS Montgomery multiply over `n =
m.len` full 2^64 limbs (the `x86_64-mont5` technique: `MULX` for the widening
products, `ADCX` for the add carry chain, `ADOX` for the mul carry chain — two
independent flag chains that keep both carries live without stalls). A
dedicated squaring (`asm_core.montSqr`, SOS over the shared `mulRow` row
primitive) was added on top — see "Dedicated squaring" under Threats/caveats.
The signature is final; only the body changes. Its result
is the same `[]u64` the portable CIOS returns, so a wrong core **cannot**
typecheck-and-silently-pass: the differential harness compares it limb-for-limb
against the proven-vs-CPython oracle.

Dispatch: `montMul` routes to the asm core iff `builtin.cpu.arch == .x86_64 and
featureSetHas(.adx) and featureSetHas(.bmi2)` **and** the gate is on; every other
target (aarch64/armv7/mips/…) runs the portable CIOS forever.

## Constant-time contract

Same guarantee `ff` gives (best-effort CT), enforced structurally:

- `montMulCios`: fixed `L²` inner iterations; the reduction is `condSubTop`, a
  masked unconditional subtract, never an `if`.
- `powMont`: fixed window count over ALL exponent bits; unconditional multiply
  per window; branchless 32-entry table gather; no early exit on leading zeros.
- `limbs.cmp`: inspects every limb regardless of where the values first differ.
- `add`/`sub`: conditional add/subtract via a mask, no data-dependent branch.

"Structurally" is not enough on its own, and this module has the measurement to
prove it — see the section below. Every secret-derived mask in `montint.zig`
(the `powMont` gather mask, `condSubTop`'s subtract mask, `sub`'s add-back mask)
is laundered through the `blackBox` inline-asm barrier, because without it LLVM
recovers `mask ∈ {0, ~0}` and turns the masked code back into a branch.

The amd64 core inherits the contract — the CIOS instruction schedule is fixed
and the final subtract must stay a `CMOV`/masked select, not a `Jcc`.

### MEASURED 2026-08-13: found leaking on the portable path, fixed, re-measured

`scripts/ctgrind.sh montint` (harness: [`src/ctgrind_harness.zig`](src/ctgrind_harness.zig))
is the first timing-audit tool ever run against this module. It found the
"enforced structurally" claim FALSE on the portable path at ReleaseFast, in two
of the four bullets above. Both are now repaired and re-measured; **every one of
the three targets reports zero in-file contexts, with no residual.**

**Full control table after the fix** (zig 0.16.0, valgrind 3.26.0, x86_64 +
ADX/BMI2, ReleaseFast, 2026-08-13; `in-file` = memcheck CONTEXTS whose stack
names `montint.zig`, `limbs.zig` or `asm_core.zig`):

| target | modulus | dispatch | `-fvalgrind` | tainted | total | in-file (was) | exit |
|---|---|---|---|---|---|---|---|
| `small` | `Modint(256)`, L=4 | portable CIOS (both cutoffs missed) | yes | **yes** | 8 | **0** ✅ *(was 7)* | 99 |
| `small` | | | yes | no | 0 | 0 | 0 *(control)* |
| `small` | | | **no** | yes | 0 | 0 | 0 *(trap)* |
| `portable` | `Modint(1024)`, L=16 | portable CIOS + `montSqrCios` | yes | **yes** | 2 | **0** ✅ *(was 5)* | 99 |
| `portable` | | | yes | no | 0 | 0 | 0 *(control)* |
| `portable` | | | **no** | yes | 0 | 0 | 0 *(trap)* |
| `asmcore` | `Modint(2048)`, L=32 | `asm_core.montMul`/`montSqr` | yes | **yes** | 2 | **0** ✅ *(was 0)* | 99 |
| `asmcore` | | | yes | no | 0 | 0 | 0 *(control)* |
| `asmcore` | | | **no** | yes | 0 | 0 | 0 *(trap)* |

`small` and `portable` taint both operands / both the base and the EXPONENT;
`portable` and `asmcore` run a full `powMont`. The totals stay non-zero (8 / 2 /
2) because the harness prints its results through a hex formatter that is not
constant-time — that is the propagation witness which makes the in-file zeros
readable, and `total_min` in `scripts/ctgrind-expected.tsv` asserts it fired.

**What the 7 and the 5 were.** Every one was the same shape — LLVM recovered
`bit ∈ {0,1}` from a borrow, concluded the mask is `0` or all-ones, and rewrote
the masked code as a branch on that bit:

- `condSubTop` — the final conditional subtract of every `montMulCios`,
  `montSqrCios`, `add` and `doubleMod`. Disassembly at the reported address:
  `cmp %rdx,%rsi; setb …; testb $0x1,…; jne` skipping the entire store block
  (and at L=16 the block is an AVX `vmovups` pair, so the branch is
  unmistakable). This is the **Montgomery final-subtraction leak** — the branch
  reveals, per multiply, whether the pre-reduction value was `≥ m`. 6 of the 7
  `small` contexts and all 5 `portable` contexts.
- `sub` (`montint.zig`, inlined `limbs.subInto`) — the masked add-back of `m` on
  borrow, compiled to `test $0x1,%dil; je`. The 7th `small` context.

In `powMont` the leak fired on **every** window: 3 contexts via `montMulCios`
(`toMontgomery`, the table build, the per-window multiply) plus 1 via
`montSqrCios` (the 5 squarings per window) plus 1 via `fromMontgomery`.

**Blast radius, while it was live.** The dispatch cutoff `asm_min_limbs = 32`
means the portable path is the DEFAULT for: every non-amd64 target (all `L`);
every modulus `< 2048-bit` on amd64 — which by `rsa`'s own dispatch comment is
exactly **RSA-2048 CRT signing/decryption, whose mod-p and mod-q halves run at
L=16** with the secret CRT exponents `dP`/`dQ`; plus `paillier`,
`threshold_ecdsa`'s `powCt`, and the pairing-field sizes (L=4/6) the small-L
comment calls out as ones that "MUST stay portable".

#### What actually fixed it — and what did not

The obvious hypothesis was structural: `asm_core.condSub` reports zero because
its second pass subtracts `m & smask` *unconditionally* instead of selecting
between two buffers, so write `condSubTop` that way too. **Measured, that
hypothesis is wrong.** Rewriting `condSubTop` into `asm_core.condSub`'s exact
two-pass shape moved the counts by nothing at all: `small` 7 → 7,
`portable` 5 → 5. At a comptime-known `L` the loops fully unroll and LLVM still
recovers `smask ∈ {0, ~0}`, sees that subtracting an all-zero operand is a no-op,
and hoists the pass behind the same branch. `asm_core.condSub` escapes only
because its `n` is a runtime slice length.

`sub` is the same story from the other direction: it *already* added `m & mask`
unconditionally and was compiled to a branch anyway.

What fixed both was the `blackBox` optimization barrier (`montint.zig`), applied
to the subtract mask in `condSubTop` and to the add-back mask in `sub` — the same
defence `powMont`'s table gather already used and `k256/src/field.zig` cites by
commit hash. Isolated by measurement:

| variant | `small` | `portable` | `asmcore` |
|---|---|---|---|
| original select-between-buffers, no barrier | 7 | 5 | 0 |
| two-pass masked form, no barrier | 7 | 5 | 0 |
| original select-between-buffers **+ barrier** | 0 | 0 | 0 |
| two-pass masked form **+ barrier** (shipped) | **0** | **0** | **0** |

So the barrier is the load-bearing half and the two-pass rewrite is neither
necessary nor sufficient. The two-pass form ships anyway because it drops the
second `Elem` scratch buffer off the stack and makes the function structurally
identical to the sibling asm core — but the SPEC should not claim it as the fix,
because it is not.

**The measurement has teeth** (positive controls, each reverted and `cmp`-verified
byte-identical afterwards):

| injected defect | effect |
|---|---|
| `if (a[j] == 0) continue;` in `montMulCios`'s inner loop | `small` 7 → 27, `portable` 5 → 69, 20 new contexts at the mutated line |
| `if (digit != 0)` around `powMont`'s window multiply | `portable` 5 → 6 and **`asmcore` 0 → 1**, at the mutated line |
| `asm_core.condSub`'s masked pass 2 → `if (under == 1) return;` | **`asmcore` 0 → 5**, at `asm_core.zig:491`, reached from both `montMulAmd64` and `montSqrAmd64` — which also proves the taint really propagates *through* the inline-asm Montgomery blocks |
| **after the fix:** `condSubTop` restored to the old select-between-buffers form | `small` 0 → **6**, `portable` 0 → **5**, at `condSubTop` — the defect class is still detectable and the barrier is what removed it (the 7th `small` context stays away because `sub` is separately fixed, which is also how the 7 splits 6 + 1) |

A null result worth recording: replacing `sub`'s masked add-back with an explicit
`if (borrow == 1)` changed **nothing** (7 → 7) — because that site was already
compiled to a branch. A control that lands on already-red code proves nothing;
the useful controls above all land on code that is green at baseline.

**Standing caveat.** This is a property of one compiler on one target at one
optimize level, not a theorem. `blackBox` denies LLVM the range fact it needs
today; nothing stops a future backend from finding another route. The value of
the harness is that it is committed and re-runnable, so the next regression is
caught the same way this one was.

## Verification harness (teeth)

1. **KAT vs an external oracle.** `mul` and `powMont` are byte-exact against
   `kat_vectors.zig` at **256/512/2048/4096 bits**. The vectors come from an
   INDEPENDENT external oracle — CPython's arbitrary-precision integers
   (`(a*b)%m`, `pow(a,e,m)`), which share no code with this module and are
   numerically identical to OpenSSL `BN_mod_mul`/`BN_mod_exp`. This is the same
   cross-language anchoring the `vdf` audit used (`pow(5,2**T,N)`); no libcrypto
   dev headers are installed on the audit host, so a direct C/OpenSSL generator
   is not available, but the function computed is identical. Moduli are random
   ODD composites (the arbitrary-odd case RSA/Paillier exercise), not primes.
2. **asm-vs-portable differential** (the anti-self-consistency anchor). For 5000
   random `(a,b,odd-N)` the gated core must equal `montMulCios` bit-for-bit.
   SKIPs until `gate.asm_core_implemented` — a skip is not a green light.
3. **Positive control — BrokenMont.** A byte-for-byte copy of CIOS with the
   final conditional subtract removed disagrees with the oracle on random inputs
   and only ever by exactly `m` (an unreduced residue) — proving the reduction
   is load-bearing and the equality checks have teeth. Runs and PASSES today.
   (The `limbs` Karatsuba anchor is likewise real teeth: it caught an odd-split
   bug during development.)
4. **CT smoke + `condSubTop` boundary coverage.** `kat_test.zig`'s smoke test
   pins `(m−1)+1 == 0`, `0−1 == m−1`, `(m−1)² mod m == 1` — but it uses
   `m = 1_000_003` inside a 128-bit element, where `a+b < 2m ≪ B^L` always, so
   the carry word `top` is 0 in every case it covers and the `top = 1` half of
   the borrow chain had no test. `montint.zig` now adds three that do, against a
   FULL-WIDTH modulus where `top = 1` is reachable: the six hand-checked
   boundaries (`v == m`, `v == m−1`, `top=1` with all-zero `v`, the range top
   `2m−1`, all-ones limbs, all-zero limbs), a 12 800-sample differential against
   an independent wide compare-and-subtract built from `limbs.zig` (asserting
   both arms fire and that the postcondition `result < m` holds), and one
   constructed pair for the borrow term that random sampling reaches with
   probability ~2⁻⁶⁴ — a limb where `v[i] == m[i]` with a borrow coming in.
   That last one is not decoration: dropping `s2[1]` from the outgoing borrow
   left the KATs, both differentials, the BrokenMont control and the random
   sweep **all green**, and is caught only by the constructed case.
   **The same term exists in `asm_core.condSub`, and was equally untested** —
   this conditional subtract is written twice in the module, and in both copies
   the `s[1] | s2[1]` borrow is easy to drop and nearly impossible to notice:
   `b2 = s[1]` alone kept the entire suite green in each. `asm_core.zig` now
   carries the mirror-image constructed pair, built at `n = 32` (the smallest
   width the dispatch routes there) against a full-width modulus — which also
   discharges the `value < 2m` precondition for free, since `m ≥ 2^2047` makes
   `2m ≥ B^32`. Each test fails under its own copy's mutation and nothing else
   does.
   A green boundary test still says nothing about branch structure, which is
   exactly why item 5 exists.
5. **ctgrind (valgrind/memcheck).** `scripts/ctgrind.sh montint` — three
   dispatch sizes (L=4 / L=16 / L=32), each as a claim row plus an untainted
   control and a no-`-fvalgrind` trap. Rows recorded in
   `scripts/ctgrind-expected.tsv`; `zig build check-ctgrind` compiles the harness
   so it cannot rot. This is the item that found the `condSubTop` branch, and
   the only item that can tell whether it stays fixed — items 1–4 were all green
   for the entire life of the defect.

## Benchmarks — the zig-vs-OpenSSL table (this host, ReleaseFast)

Host: Intel i7-7920HQ (Kaby Lake, mobile). All four columns measured on the
**same** host; numbers are noisy (turbo/thermal on a laptop) — read them as
ratios. **`modmul` = one Montgomery multiply** `a·b·R⁻¹ mod m` with `a,b` already
in the Montgomery domain, so it is directly comparable to OpenSSL
`BN_mod_mul_montgomery`. **`modexp` = a full-width constant-time exponent**
(`BN_mod_exp_mont_consttime`, *not* RSA-CRT) — no CRT normalization needed, this
is a true full-width modexp on both sides. Columns: **portable-Zig** (`montMulCios`)
· **asm-Zig** (the `MULX/ADX` core) · **OpenSSL 3.5.5** (libcrypto, same host) ·
**`std.crypto.ff`** (the "before" the audit measured). The Zig columns come from
`bench.zig` (`MONTINT_BENCH=1`); OpenSSL from a small libcrypto driver.

**modmul** (ns/op — one Montgomery multiply):

| bits | portable-Zig | asm-Zig | OpenSSL | std.crypto.ff |
|---|---|---|---|---|
| 256  | **30**  | 73   | 52    | 785    |
| 512  | **147** | 156  | 99    | 2 032  |
| 2048 | 2 094   | **1 463** | 1 106 | 24 591 |
| 4096 | 9 610   | **5 467** | 3 857 | 98 194 |

**modexp** (full-width, constant-time):

| bits | portable-Zig | asm-Zig | OpenSSL | std.crypto.ff |
|---|---|---|---|---|
| 256  | **9.1 µs** | 22.1 µs | 18.8 µs | 61.3 µs |
| 512  | **87 µs**  | 102 µs  | 38 µs   | 342 µs  |
| 2048 | 5.15 ms | **3.43 ms** | 1.91 ms | 16.4 ms |
| 4096 | 44.1 ms | **26.7 ms** | 14.9 ms | 125 ms  |

(**bold** = the path `montMul`'s small-L dispatch actually selects at that size,
see below.) Honest OpenSSL multiple of the **shipped** path:

| size | modmul vs OpenSSL | modexp vs OpenSSL |
|---|---|---|
| 256  | 0.58× (montint **faster**) | 0.48× (montint **faster**) |
| 512  | 1.48× | 2.3× |
| 2048 | 1.32× | **1.79×** |
| 4096 | 1.42× | **1.79×** |

Everything is inside the ≤3× goal. **Bottom line:** the bulk of the win over the
`ff` baseline is the Montgomery-resident portable CIOS on full 2^64 limbs
(ff→portable ≈ **3.2×** at 2048-bit modexp, ≈ **12×** at 2048-bit modmul); the
asm core adds ≈ **1.5×** on top at 2048-bit (portable 5.15 ms → asm 3.43 ms
modexp; 2 094 ns → 1 463 ns modmul). Combined, the shipped path is **≈1.8×
OpenSSL** full-width at 2048/4096-bit modexp and **1.3–1.4× OpenSSL** at modmul —
and it *beats* OpenSSL outright at 256-bit — versus the **8–29×** the `ff`-backed
modules pay today. (Prior CRT caveat retired: this table measures full-width
`BN_mod_exp` directly, so there is no apples-to-oranges CRT normalization. For
reference, OpenSSL rsa2048 **CRT sign** on this host is ≈ 624 µs ≈ ¼ of a
full-width 2048 modexp, consistent with the 1.91 ms measured here.)

## 256-bit regression / small-L dispatch

The asm core is **not** universally faster. The `MULX/ADX` block runs
runtime-`n` loops (trip-count setup, remainder handling, the mul→reduce register
shuffle), whereas the portable CIOS is comptime-**fully unrolled** for the fixed
`L` with zero loop bookkeeping. At small `L` that overhead dominates the handful
of limb products, so the asm modmul is **~2.4× SLOWER at 256-bit** (73 vs 30 ns),
~1.06× slower at 512-bit, ~1.07× slower at 1024-bit, and only pulls ahead at
2048-bit (1.43× faster) and 4096-bit (1.75× faster). Measured breakeven on this
host is **~1.5–2k bit** — higher than the canonical ~512-bit `mont5` breakeven, a
mobile-CPU/turbo artifact.

**This matters for the pairing fields.** `bn254` Fp (254-bit → L=4) and
`bls12_381` Fp (381-bit → L=6) live exactly in the small-L regime where asm is
2×+ slower, so they MUST NOT use it. `montMul` therefore applies a comptime
cutoff — `asm_active AND L >= montint.asm_min_limbs` (**= 32**, i.e. ≥2048-bit) —
routing every smaller modulus to the portable CIOS and reserving the asm core for
the large RSA/Paillier/VDF moduli where it robustly wins. The asm core remains
correct at every `L` (the differential exercises `n ∈ {1,2,3,4,5,8,16,17,32,33,64}`
incl. leading-zero-limb moduli and squaring aliasing) — the cutoff is purely a
speed dispatch, not a correctness bound.

## Threats / caveats

- **amd64-only fast path.** The `MULX/ADX` core lands only on x86-64 with the ADX
  + BMI2 feature flags; every other target (aarch64/armv7/mips/…) runs the
  portable CIOS forever, and even on amd64 the small-L dispatch (see above) keeps
  moduli `< 2048-bit` — including the pairing fields — on the portable path.
- **Best-effort CT, like `ff` — measured, not asserted.** The contract is
  structural, and a sufficiently clever optimizer *did* in fact reintroduce a
  branch: until 2026-08-13 the portable `condSubTop` and `sub` compiled to
  secret-dependent `jne`s, which the hand-read disassembly missed because it was
  of `asm_core.montMul` — code an `L < asm_min_limbs` modulus never reaches. For
  that function the old reading still holds: every conditional branch is on the
  PUBLIC limb count `n` (asm loop trip counts, the outer limb loop, the
  `condSub` loop counters + its unrolled-remainder `n`-parity test) and its final
  subtract really is a `setb`+mask masked select. The portable path is now fixed
  and all three dispatch sizes measure zero in-file contexts — see
  "MEASURED 2026-08-13" under the constant-time contract above for the tables,
  the controls and what did *not* fix it. The sentence "no timing audit tool has
  been run" that used to close this bullet was the reason the defect survived,
  and it is now `scripts/ctgrind.sh montint --check` instead.
- **No base blinding / fault countermeasures.** This is a modular-arithmetic
  primitive, not a signing scheme; blinding (rsa F2) and CRT fault-checks
  (rsa F3) are the consumer's responsibility, layered on top.
- **Dedicated squaring — DONE, portable AND asm.** The portable constant-time
  dedicated Montgomery square (`montSqrCios`, SOS: the symmetric `a[i]·a[j]`
  off-diagonal products computed once and doubled, plus the diagonal squares,
  then a Montgomery reduce) backs `montSqr`/`powMont` for
  `sqr_min_limbs ≤ L < asm_min_limbs` **and** all `L` on non-amd64 targets
  (~1.15–1.23× vs the portable multiply at L=8…64 on this host; wins rsa-2048
  CRT sign at L=16 and every large-modulus op on non-amd64/OpenWRT). The
  dedicated **asm** square (`asm_core.montSqr`) now serves `L ≥ asm_min_limbs`
  on amd64: same SOS phase order as the portable oracle, with both O(L²) inner
  loops — the off-diagonal product rows and the word-serial REDC rows — run on
  `asm_core.mulRow`, the `MULX/ADCX/ADOX` dual-carry-chain accumulate row
  (verbatim the labels-1–4 half of `ciosIter`). The classic `×2`+diagonal carry
  pitfall is structurally absent: the doubling is a separate funnel-shift pass
  over the COMPLETED cross-product sum (outside any carry chain), and the
  diagonal add + per-row tail carries are the same Zig `u128` arithmetic as the
  oracle. Anchored by a three-way differential (asm sqr == `montSqrCios` ==
  asm `montMul(a,a)`, thousands of random trials at L∈{1,2,3,4,5,8,16,17,32,
  33,34,35,48,64} — every rem class of the reduction row — plus carry-saturation
  edges, Debug AND ReleaseFast) and an asm-rows positive control (a square with
  the doubling omitted goes RED). Measured (this host, ReleaseFast, same-run
  A/B): asm sqr beats asm `montMul(a,a)` ~1.10–1.13× at L=32 and ~1.12–1.15× at
  L=64 → modexp-2048 ≈ 3.23 ms (was ≈ 3.5), modexp-4096 ≈ 22.3–24.4 ms (was
  ≈ 26.5) ⇒ ≈ **1.7×**/**1.5–1.6×** OpenSSL (from 1.8×/1.8×); rsa-4096 CRT sign
  ≈ −10 % (CRT halves are L=32), rsa-2048 CRT sign unchanged (halves are L=16,
  already on the portable square).
- **Deferred:** the large-size SOS+Karatsuba
  modmul path, tuning the small-L cutoffs per-µarch (`asm_min_limbs`/
  `sqr_min_limbs` are single-host measurements), and a possible
  dynamic-limb-count modulus (today `L` is fixed by `max_bits`; a small modulus
  in a wide `Modint` wastes work). Consumer note: `rsa`/`paillier`/
  `threshold_ecdsa` and vdf's Montgomery-resident `prove`/`verify` all call
  `montint`'s `montSqr`/`powMont`, so they inherit this change automatically (no
  consumer edit) — the win lands wherever the dispatch picks a dedicated square
  (asm at L≥32 on amd64, portable at L=8..31 on amd64 and at all L on
  non-amd64). vdf's `eval` hot loop is the
  exception: `group.square` there still calls `std.crypto.ff` directly, so it
  does NOT benefit — migrating that loop to a `montint` Montgomery-resident
  square is a separate small vdf-side follow-up.

## Provenance

Clean-room from public algorithm descriptions: Montgomery multiplication (Koç et
al. CIOS), the `x86_64-mont5` `MULX/ADCX/ADOX` technique (OpenSSL, studied as a
design reference — recorded in `NOTICE`), and the `std.crypto.ff` public API for
shape. KAT vectors from an independent CPython-bignum re-derivation (no
third-party source ported). See `NOTICE`.

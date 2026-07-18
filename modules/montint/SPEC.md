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
independent flag chains that keep both carries live without stalls). Optionally
a dedicated squaring. The signature is final; only the body changes. Its result
is the same `[]u64` the portable CIOS returns, so a wrong core **cannot**
typecheck-and-silently-pass: the differential harness compares it limb-for-limb
against the proven-vs-CPython oracle.

Dispatch: `montMul` routes to the asm core iff `builtin.cpu.arch == .x86_64 and
featureSetHas(.adx) and featureSetHas(.bmi2)` **and** the gate is on; every other
target (aarch64/armv7/mips/…) runs the portable CIOS forever.

## Constant-time contract

Same guarantee `ff` gives (best-effort CT), enforced structurally:

- `montMulCios`: fixed `L²` inner iterations; the reduction is `condSubTop`, a
  masked limb-select, never an `if`.
- `powMont`: fixed window count over ALL exponent bits; unconditional multiply
  per window; branchless 32-entry table gather; no early exit on leading zeros.
- `limbs.cmp`: inspects every limb regardless of where the values first differ.
- `add`/`sub`: conditional add/subtract via a mask, no data-dependent branch.

The amd64 core inherits the contract — the CIOS instruction schedule is fixed
and the final subtract must stay a `CMOV`/masked select, not a `Jcc`.

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
4. **CT smoke.** Boundary behavior of the CT reduction (`(m−1)+1 == 0`,
   `0−1 == m−1`, `(m−1)² mod m == 1`) plus the reasoning-anchored no-secret-branch
   note.

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
- **Best-effort CT, like `ff`.** The contract is structural; a sufficiently
  clever optimizer could in principle reintroduce a branch. The ReleaseFast
  `montMul` disassembly was checked: every conditional branch is on the PUBLIC
  limb count `n` (asm loop trip counts, the outer limb loop, the `condSub` loop
  counters + its unrolled-remainder `n`-parity test) and the final subtract is a
  `setb`+mask masked select — no secret-dependent `Jcc`. No timing audit tool has
  been run; the guarantee is best-effort, as with `ff`.
- **No base blinding / fault countermeasures.** This is a modular-arithmetic
  primitive, not a signing scheme; blinding (rsa F2) and CRT fault-checks
  (rsa F3) are the consumer's responsibility, layered on top.
- **Portable dedicated squaring — DONE; dedicated ASM squaring — deferred.** A
  portable constant-time dedicated Montgomery square (`montSqrCios`, SOS: the
  symmetric `a[i]·a[j]` off-diagonal products computed once and doubled, plus
  the diagonal squares, then a Montgomery reduce) now backs `montSqr`/`powMont`
  for `sqr_min_limbs ≤ L < asm_min_limbs` **and** all `L` on non-amd64 targets.
  It is ~1.15–1.23× faster than the portable multiply (L=8…64 on this host) and
  speeds up **rsa-2048 CRT sign** (L=16 primary amd64 case) and every
  large-modulus op on non-amd64/OpenWRT. A dedicated **asm** square (MULX/ADCX/
  ADOX with the doubling+diagonal structure) is still deferred: on amd64 at
  `L ≥ asm_min_limbs` the existing asm `montMul(a,a)` still beats a *portable*
  square, so those sizes (rsa-4096, paillier, vdf, threshold_ecdsa) route to it
  unchanged. The remaining win there requires the asm square — the classic
  pitfall is carry propagation through the `×2` and the diagonal add; it is NOT
  shipped because it was not proven bit-exact within this change and a wrong CT
  square in the RSA hot path is unacceptable. Follow-up scope: reuse the
  `ciosIter` register plan for the reduction row + a new symmetric-product row
  that doubles off-diagonal partials, oracle = `montSqrCios`.
- **Deferred:** the dedicated asm squaring (above), the large-size SOS+Karatsuba
  modmul path, tuning the small-L cutoffs per-µarch (`asm_min_limbs`/
  `sqr_min_limbs` are single-host measurements), and a possible
  dynamic-limb-count modulus (today `L` is fixed by `max_bits`; a small modulus
  in a wide `Modint` wastes work). Consumer note: `rsa`/`paillier`/
  `threshold_ecdsa` and vdf's Montgomery-resident `prove`/`verify` all call
  `montint`'s `montSqr`/`powMont`, so they inherit this change automatically (no
  consumer edit) — the win lands wherever the dispatch picks a portable square
  (rsa-2048 CRT L=16 on amd64; all L on non-amd64). vdf's `eval` hot loop is the
  exception: `group.square` there still calls `std.crypto.ff` directly, so it
  does NOT benefit — migrating that loop to a `montint` Montgomery-resident
  square is a separate small vdf-side follow-up.

## Provenance

Clean-room from public algorithm descriptions: Montgomery multiplication (Koç et
al. CIOS), the `x86_64-mont5` `MULX/ADCX/ADOX` technique (OpenSSL, studied as a
design reference — recorded in `NOTICE`), and the `std.crypto.ff` public API for
shape. KAT vectors from an independent CPython-bignum re-derivation (no
third-party source ported). See `NOTICE`.

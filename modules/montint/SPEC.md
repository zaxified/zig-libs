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

## The scaffold cut-line (what the Fable agent fills)

Exactly one function is gated (`gate.asm_core_implemented = false`):

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

## Benchmarks (this host, ReleaseFast, PORTABLE path — pre-asm baseline)

| op | 2048-bit | 4096-bit |
|---|---|---|
| modmul (a·b mod m) | 4.4 µs | 18.5 µs |
| modexp (full-width exponent) | 5.46 ms | 44.1 ms |

OpenSSL reference on the same host (`openssl speed`): rsa2048 CRT **sign** 624
µs, rsa4096 sign 4.34 ms; rsa2048 **verify** 18 µs, rsa4096 verify 63 µs. Note
the comparison is not apples-to-apples: OpenSSL's private op is **CRT** (two
half-width modexps ≈ 4× less work than a full-width modexp), and its public op
uses a tiny `e = 65537`. Even so, the portable path already improves markedly on
the `std.crypto.ff` baseline the audit measured (rsa2048 CRT sign 19.33 ms via
ff), i.e. the full-limb + 5-bit-window portable modmul/modexp is several× faster
than ff **before any asm**. The `≤3× OpenSSL` target is the asm core's job; the
owner-verify + Fable phases produce the real zig-vs-OpenSSL table.

## Threats / caveats (scaffold)

- **Not yet the fast path.** amd64 asm core is a stub; today everything runs the
  portable CIOS. No performance claim beyond the portable numbers above.
- **Best-effort CT, like `ff`.** The contract is structural; a sufficiently
  clever optimizer could in principle reintroduce a branch. No timing audit has
  been run. The masked selects follow the `ff` pattern.
- **No base blinding / fault countermeasures.** This is a modular-arithmetic
  primitive, not a signing scheme; blinding (rsa F2) and CRT fault-checks
  (rsa F3) are the consumer's responsibility, layered on top.
- **Deferred:** the asm core (Fable), a dedicated asm squaring, the large-size
  SOS+Karatsuba modmul path, and a possible dynamic-limb-count modulus (today
  `L` is fixed by `max_bits`; a small modulus in a wide `Modint` wastes work).

## Provenance

Clean-room from public algorithm descriptions: Montgomery multiplication (Koç et
al. CIOS), the `x86_64-mont5` `MULX/ADCX/ADOX` technique (OpenSSL, studied as a
design reference — recorded in `NOTICE`), and the `std.crypto.ff` public API for
shape. KAT vectors from an independent CPython-bignum re-derivation (no
third-party source ported). See `NOTICE`.

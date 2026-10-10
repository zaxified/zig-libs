# montint — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — **NO CONSUMER-VISIBLE CHANGE:** deterministic fuzz driver (`MONTINT_FUZZ`, `src/fuzz_test.zig`) with `std.math.big` as a differential oracle: the byte loaders (`fromBytesBE`, `elementFromBytesBE`, `elemFromBytesBE`, `loadBE`) give the exact accept / `EvenModulus` / `ModulusTooSmall` / `NonCanonical` / `Overflow` verdict big integers predict, and `Modint(256)` / `DynModint(2048)` add, sub, neg, mul, sq, pow, powPublic, inverse and `reduceBytesBE` match big-integer results (the dispatching Montgomery multiply and square also match the portable CIOS ones). 200,000 runs per harness clean in ReleaseSafe.

- **2026-10-10** — perf: fixed-`L` MULX/ADX kernels `asm_core.montMulFixed`/`montSqrFixed` (rows unrolled at comptime, outer loop in asm, laundered `condSubFixed`), dispatched by `Modint.montMul`/`montSqr` at `L >= fixed_min_limbs` (16; the square up to `sqr_fixed_max_limbs` = 32). 1.2–1.7× faster per op at L = 16..64; nothing below 1024 bits changes. Differential vs the portable CIOS at L = 2..64; ctgrind `asmcore` 0 in-file, `portable` target moved to `Modint(512)` (output re-pinned). No API change (new `pub` consts `fixed_min_limbs`, `asm_core.sqr_fixed_max_limbs`).
- **2026-10-06** — **BREAKING: `nt.divExact` returns
  `error{NotDivisible}![n]u64`** (was `[n]u64`, garbage for a zero or
  non-dividing divisor): the quotient is checked as `q·b = a` over the full
  `2n`-limb product and `b ≠ 0`, constant-time up to that one verdict.
  Migration: `try`, or map the error — `paillier`'s CRT-exponent derivation,
  the only caller, now returns `error.InvalidPrimes` on it (updated in the
  same change). Review 2026-10-03 (L4).

- **2026-10-06** — **Review 2026-10-03 LOW items L1, L2, L3, L5 fixed** (no
  signature change). `DynModint.isProbablePrime(random, 0)` returns `false`
  instead of "prime" for every odd modulus (L1). Miller-Rabin witnesses are
  near-uniform over `[2, m − 2]` — `bits + 64` random bits reduced mod `m`,
  `0`/`1`/`m − 1` masked to `2`, no retry loop and no compare against `m` —
  instead of the lower half `[2, 2^(bits−1))`, so the `4^−rounds` bound holds
  as stated; the draw consumes a different amount of randomness, so a seeded
  prime search can land on a different prime (L2). `DynModint.inverse`
  refuses `a ≥ m` in its constant-time verdict, including a non-zero limb
  above the slot, which used to be dropped and the inverse of the truncated
  value returned (L3). `DynModint.toBytesBE` with `out` shorter than the
  modulus and `Modint.toBytesBE` with `out.len ≠ encoded_bytes` now `@panic`
  in every optimize mode; the old `std.debug.assert` compiled to
  `unreachable` in ReleaseFast (a probe crashed with SIGSEGV rather than
  truncating) (L5). New tests for L1–L4 fail on the old code; L5's pins the
  accepted widths (no in-process test can catch a panic — a ReleaseFast
  probe showed the old crash and the new panic).

- **2026-10-05** — **Re-survey (documentation only, no code change): scope
  mvp → core.** `SPEC.md`'s `## Compared with` re-checked against
  crypto-bigint 0.7.5, OpenSSL 4.0.3 and `std.crypto.ff`, with
  `filippo.io/bigmod` and `num-bigint` added: the main use cases (CT
  modexp over run-time odd moduli, public-exponent verify, CT inversion,
  gcd/lcm, Miller-Rabin key generation) are covered and in use by `rsa`,
  `paillier`, `threshold_ecdsa` and `vdf`. Remaining gaps filed under
  Backlog: batched divsteps (per-message inversion speed), square root mod a
  prime, Baillie-PSW, CT `compare`/`isOdd`, and the 2026-10-03 review's five
  LOW items (all still open). The Audit line now records that review and the
  2026-10-03 mutation runs. Stale caveats corrected: `vdf`'s `eval` loop
  already runs on `montint` (`Modint.montSqr`), not `std.crypto.ff`, and the
  dynamic-limb-count modulus listed as deferred shipped as `DynModint`.

- **2026-10-03** — **`montint.nt` (constant-time gcd, lcm, odd part, exact
  division on limb arrays) and `DynModint.isProbablePrime`.** `nt.gcd`/`lcm`
  run divsteps on the odd parts and shift the powers of two back in;
  `nt.divExact` divides by any exact divisor, even ones included;
  `isProbablePrime(random, rounds)` is Miller-Rabin constant-time in the
  modulus's value along a prime's path (masked `m − 1 = d·2^s`, montint
  ladder, verdicts OR-ed per round). `DynModint.inverse`'s masked-limb helpers
  moved into `nt.zig` (shared, no behaviour change). Used by `rsa`'s and
  `paillier`'s key derivation and by all three prime searches.

- **2026-10-03** — **Constant-time modular inversion: `DynModint.inverse` and
  `inverseOfModulus`.** `inverse(a, out) bool` is `a⁻¹ mod m` by
  Bernstein–Yang divsteps (masked blends, the paper's step bound from the
  modulus's public bit length, verdict `g = 0 ∧ f = ±1`);
  `inverseOfModulus(n, out) bool` is `m⁻¹ mod n` for any `n ≥ 2`, even
  included (odd-side inverse, then a Hensel exact division). Constant-time in
  the operand and the modulus value up to the verdict (ctgrind `dyn`: no new
  context). ~3.5 ms at 2048 bits (≈ one modexp) — for key setup and provers.
  `divExact`'s Newton step moved into a shared helper (no behaviour change).

- **2026-10-03** — **`DynModint` for secret primes whose length is known.**
  `fromLimbsBits(v, nbits)` takes the bit length from the caller (the key
  size) and checks it, oddness and `≥ 3` in one combined verdict — nothing
  scans the secret value for its length, and `Modint`'s own odd/`≥ 3`
  branches are skipped through the new `Modint.fromElemUnchecked`. The bit
  length is stored at construction (`bits()` no longer rescans). New CT
  `DynModint.select` (asm-laundered mask). Used by `threshold_ecdsa`'s
  constant-time Πmod prover and Miller-Rabin.

- **2026-10-02** — **New `DynModint(max_bits)`: a run-time modulus with a
  constant-time element API.** The modulus value AND its limb count are chosen
  at run time (slots of 4 limbs, dispatched to the matching `Modint`); elements
  are normal-domain `[max_limbs]u64`. Branchless `loadBE`, canonical
  `elemFromBytesBE`, `toBytesBE`, `reduceLimbs`/`reduceBytesBE` of any width
  (Horner over `min(64, bits−1)`-bit digits, so every `montMul` operand stays
  `< m` down to `m = 3`), `add`/`sub`/`neg`/`mul`/`sq`, `pow` (CT), `powPublic`
  (variable-time public exponent — closes that backlog item), CT `isZero`/`eql`
  and `divExact` (Hensel exact division — Paillier's L-function). Replaces the
  three private "MontParams + slot" copies in `rsa`/`paillier`/`threshold_ecdsa`,
  whose secret arithmetic moves off `std.crypto.ff` with it; `elemFromFf`/
  `elemToFf`/`fromFf` bridge `std.crypto.ff` values by a positional limb repack. Differential tests against
  `std.math.big.int` at 2…8192-bit moduli; new ctgrind target `dyn` (secret
  modulus, both the portable L=16 and asm L=32 slots): 2 in-file contexts, both
  `elemFromBytesBE`'s accept/reject.

- **2026-10-02** — **New `Field(p)`: a constant-time prime field over `Modint`.**
  `GF(p)` for a comptime prime, Montgomery-resident, built only from `montMul`/
  `montSqr`/`add`/`sub`/`powMont`: canonical `fromBytesBE`, `toBytesBE`,
  `reduceBytesBE` of any width, `add`/`sub`/`neg`/`mul`/`sq`/`pow`/`inv`.
  `bls12_381.Fr` and `bn254.Fr` move onto it from `std.crypto.ff`, which ctgrind
  shows branching on secrets in ReleaseFast (`montgomeryMul`'s extra-reduction
  select, the pow window select). New ctgrind targets `field` (0 in-file but
  `inv`'s zero check) and `ffcontrol` (positive control on the ff path).

- **2026-09-08** — **Montgomery setup: R² now comes from a ladder, not 64·L more
  doublings.** `computeConstants` derived both R and R² by repeated doubling —
  128·L passes, so 4 096 of them for a 2048-bit modulus — on the reasoning that
  "R² needs 128·L doublings; obviously-correct and cheap at setup". That premise
  belongs to the CALLER, and certificate path validation does not satisfy it:
  `x509` builds a fresh `rsa.PublicKey` per chain link, so the setup was paid per
  operation and dwarfed it (measured: 606 µs of setup for a 36 µs verify).
  Writing `f(k) = 2^k mod m`, `montMul(f(a), f(b)) = f(a + b − 64L)`, so squaring
  doubles the surplus exponent and one `doubleMod` increments it — square-and-add
  over the bits of 64·L, ~log₂(64L) Montgomery multiplications where there were
  64·L doublings. **`rsa.PublicKey.fromDer` goes 813 µs → 515 µs (1.58×)** for a
  2048-bit key; every `Modint` consumer gets it.
  Constant-time is unaffected: the ladder is driven by the comptime constant
  64·L, never by the modulus, which matters because `rsa` calls this on the
  secret CRT primes `p` and `q`. The pre-change derivation is kept in-tree as the
  test oracle `r2ByDoubling`, and the new one must agree with it **bit for bit**
  across five slot widths × 24 random full-width moduli. Shortening the ladder by
  one bit turns 14 checks red; dropping the `started` guard does not, and that is
  correct — `montMul(R, R) = R`, so it is an equivalent mutant and the guard is
  an optimisation rather than a correctness condition.
  NO CONSUMER-VISIBLE CHANGE (same constants, same API).

- **2026-09-07** — **Test-only: both byte-loader fuzz harnesses were handed the
  empty string on every run.** `fuzzFromBytesBE` and `fuzzElementFromBytesBE`
  opened with `smith.bytes(&buf)` followed by
  `smith.valueRangeAtMost(u8, 0, buf.len)`. `bytes` consumes
  `@min(buf.len, in.len)` octets, so the ranged draw that followed found fewer
  than the eight it reads as a little-endian `u64` and returned the range
  MINIMUM: `len` was 0 for every input the ordinary test lane can carry, and
  neither loader ever saw a byte. Both now draw with one `smith.slice(&buf)`
  and carry a 12-seed corpus covering every member of `Error` plus the
  accepting path. Measured 2026-09-07 over that corpus: **0 of 12 seeds
  arrived non-empty before, 12 of 12 after; 0 moduli built before, 5 after; 0
  non-zero elements reduced before, 5 after; the `error.Overflow` branch was
  unreachable before (0), now 2.** ⭐ An `accepted > 0` guard would have read
  green throughout — `elementFromBytesBE("")` legitimately succeeds, the zero
  element being canonical below any modulus — so the new corpus guard pins the
  moduli built and the non-zero elements reduced, neither of which the empty
  input can produce. The buffer stays at 48 octets against `encoded_bytes` of
  32 on purpose: a buffer sized to the modulus could never reach
  `error.Overflow` at all.

- **2026-08-13** — **Re-audit follow-up: coverage and claims only — neither BREAKING nor
  BEHAVIOURAL.** No shipped code path changed; the day's timing fix was
  re-measured from scratch and holds (0 in-file contexts at all three dispatch
  sizes). What changed is what is tested and what the docs promise. (a) The
  claim below that the conditional subtract's boundary behaviour was covered "in
  **both** copies" was an overreach: `asm_core.condSub`'s **pass-1** outgoing
  borrow was still untested, and it is the copy on the amd64 asm path
  (RSA-2048/4096, `paillier`, `vdf`). Dropping its `s2[1]` term flips the
  reduction DECISION and left the whole suite green; there is now a constructed
  `n = 32` case for it. (b) `asm_min_limbs`/`sqr_min_limbs` are pinned by value
  — raising `asm_min_limbs` to 64 previously left `test-montint` and all 22
  reverse-dependency modules green while silently moving what
  `scripts/checks/ctgrind.sh` measures. (c) `blackBox`'s `@inComptime()` guard is now
  exercised by a comptime `fromElem`, and its comment states the missing
  precondition (a caller-side `@setEvalBranchQuota`). (d) `sub`'s barrier is now
  measured at L=16 and L=32, not only L=4 — L=16 is the RSA-2048 CRT width the
  fix was about; both read 0, and dropping the barrier turns each into 1.
  (e) The byte loaders' value-dependent zero-byte skip is documented at the
  source instead of only in `rsa`/`paillier` comments downstream: it is outside
  the constant-time contract, no secret reaches it today, and callers loading
  secrets must go through `fromElem` from a branchless limb load.
- **2026-08-13** — **Timing fix — neither breaking nor behavioural.** `condSubTop` (the final
  conditional subtract of every `montMulCios`, `montSqrCios`, `add` and
  `doubleMod`) and `sub`'s masked add-back were compiled by ReleaseFast into a
  branch on the secret-derived borrow — the classic Montgomery
  final-subtraction leak, revealing per multiply whether the pre-reduction value
  was `≥ m`. It sat on the portable CIOS path, which `asm_min_limbs = 32` makes
  the default for every modulus below 2048 bits on amd64 and for every non-amd64
  target: RSA-2048 CRT sign/decrypt with secret `dP`/`dQ` (L=16), `paillier`,
  and `threshold_ecdsa`'s `powCt`. Both masks are now laundered through the
  module's `blackBox` optimization barrier, and `scripts/checks/ctgrind.sh montint`
  measures 0 in-file contexts at all three dispatch sizes, down from 7 (L=4) and
  5 (L=16). Classified as **neither BREAKING nor BEHAVIOURAL**: no signature,
  error set or field changes, and no computed value changes — every input maps
  to the same output it did before, verified by the KAT/differential suite. What
  changes is only the instruction schedule. Callers who were relying on the
  documented constant-time contract were getting something weaker than the
  contract said; they now get what it said. `condSubTop` was also rewritten into
  the sibling asm core's two-pass masked form, which drops an `Elem` of stack —
  measurement says that rewrite is NOT what fixed the leak (see SPEC.md).
- **2026-08-13** — Test coverage for the conditional subtract's boundary behaviour: the existing
  smoke test could never produce a carry word, so the `top = 1` half of the
  borrow chain was untested, as was the outgoing-borrow term that only fires on
  a limb where `v[i] == m[i]` — dropping that term left the whole suite green.
  Covered now in `montint.condSubTop` and `asm_core.condSub` (the latter at
  `n = 32`, the smallest width the dispatch routes there); each is caught only
  by its own constructed case. *(The "both copies" this entry originally claimed
  was pass 2 in each; `condSub`'s pass 1 was closed by the re-audit follow-up
  above.)*
- **2026-07-21** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against an independent
  CPython bignum oracle at 256/512/2048/4096-bit.
- **2026-07-18** — Performance: gained an asm/Montgomery core (part of a collection-wide
  performance campaign that also covered the sibling `k256`/`p256`
  modules; the root changelog records no further detail than this).

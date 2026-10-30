# montint — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-30** — **BREAKING:** no-panic sweep + blind review (§ GT). `DynModint.sqrt` returns `error{SqrtWorkLimit}!bool` (new pub consts `sqrt_max_two_adicity` = 256, `sqrt_max_candidates` = 256; past either the work is refused instead of running for minutes; no consumer called it). Fixes: caller-contract asserts in `limbs`, `fromElemUncheckedBits`, `safegcd.invert`/`invert2` (`nbits`), `asm_core` slice entry points and `Field.pow` (exponent > 8L bytes) are checked panics in every mode; an even modulus in safegcd is forced odd and folded into the verdict branch-free (answers `false`, the modulus may be a secret prime). Docs: `DynModint.stack_bytes` (48/80/144 KiB at 2048/4096/8192 bits, pinned by `src/stackprobe_test.zig` in ReleaseFast), `sqrt` worst-case work, capacity = `64·max_limbs` bits. Tests: `src/sweep_test.zig`.
- **2026-10-26** — **NO CONSUMER-VISIBLE CHANGE:** `R² mod m` (every `Modint` / `DynModint` construction) is built from `R mod m` by L doublings and six `montSqr` steps (ring's `One::newRR` choice) instead of the square-and-add ladder over the bits of 64·L with `montMul(x, x)` (1 doubling + 11 multiplies at 2048 bits). Same constants bit for bit (the doubling-reference test now covers L = 1, 2, 3, 4, 8, 16, 24, 32, 48, 64, 128); step counts still depend on L alone, so the derivation stays constant-time in the modulus. A public RSA-2048 key setup is about a third cheaper; `x509`'s RSA-2048 chain verification went 65 → 56 µs.

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC brought up to Zig 0.17.0 (version statements, snippets, measurement labels).

- **2026-10-18** — Ported to Zig 0.17.0: `std.meta.Int` -> `@Int` (test); `strRepeat` branch quota scaled with length. Examples/tools ported to Zig 0.17.0 (bench `std.meta.Tuple` -> `@Tuple`).
- **2026-10-18** — **Build option `montint-asm-unroll`** (wgs request): `false`, or `-Dprofile=small`, runs every Montgomery multiply/square from 1024 bits up on the one looped asm kernel instead of straight-line asm per limb count. Same results and constant-time shape; size probe (`DynModint(8192)`, ReleaseSmall, ADX/BMI2) 319 288 → 173 104 B; modexp 1.6–2.0× slower. Default unchanged. New `tools/sizeprobe.zig` + floor row.
- **2026-10-18** — **Performance:** `safegcd.Inverter` runs the half-delta divstep bound `⌊(45907·b + 26313)/19929⌋` (sipa/safegcd-bounds `genproofhd.md`, `0 ≤ g ≤ f`; libsecp256k1's 590 at 256 bits is one below it) instead of Bernstein–Yang Theorem 11.2's original-divstep bound: 40 batches instead of 51 at 1024 bits (rsa-2048's blinding inverse), ~22 % fewer at every size. Results stay verified (`invert`'s verdict, then `x·x⁻¹ ≡ 1` in every caller), so a shortfall would refuse or redraw, never return a wrong inverse. Tests unchanged and green (big-int differential 64…4096 bits, edges, non-units); paillier and threshold_ecdsa modtests green; ctgrind counts of montint, paillier, threshold_ecdsa, ssh, k256, jwt, blindrsa unchanged.
- **2026-10-18** — **Code size:** `DynModint`'s slots are every 4 limbs up to 1024 bits, then only the key sizes 1536/2048/3072/4096/6144/8192 bits and the type's top slot (new `DynModint.slots`); `DynModint(8192)` instantiates 10 slots instead of 32. On an ADX/BMI2 CPU each slot is straight-line asm: rsa's sizeprobe (ReleaseSmall, native) 863 144 → 427 536 B by default. A modulus of a key size keeps its exact slot (same code as before); any other size runs one slot up (slower by the width ratio, e.g. 17 limbs at 24). `max_limbs` unchanged. Test: the slot lists of 4096/5000/8192-bit types and the slot each limb count picks.
- **2026-10-14** — perf (no API change), found when rsa's capacity went to 8192 bits: work that scaled with `max_bits` instead of the slot. `DynModint` results are built by `widen` (slot copy + vector-store zeroing of the tail) instead of `var out = zero` (a 1 KiB `@memset` lowers to Zig 0.16's byte-wise `compiler_rt.memset`); `loadBE` zeroes the same way; `elemFromBytesBE` subtracts over the slot and folds the limbs above it into the one verdict; `safegcd` builds, copies and wipes only the `k` live limbs of its state (it wiped the whole `K`-limb state byte by byte). `asm_core.zeroWords` is now `pub`.
- **2026-10-14** — perf: `DynModint.inverse` runs on the batched constant-time `safegcd.Inverter` (59 divsteps per transition matrix; moved from `rsa`, now `montint.safegcd`) instead of one divstep at a time (in `rsa` the same engine costs a few tens of µs at 2048 bits; not re-benched here); same contract (`a ≥ m` and non-units refused, CT in `a` and the modulus value) plus a verified `a·inv ≡ 1` before `true`; the old form is kept as a private test oracle (600 random and edge pairs, L = 4…64, same verdict and value). The engine is sized by the public slot width `64·L`, not the modulus's `nbits`: sized by `nbits` it put 72 secret-length branches into ctgrind `paillier keygen` (λ is a secret modulus there; 314 → 386, caught by `--check`, back to the pinned count). 32-bit (x86-linux) now compiles: `nt.zig` and test-helper `usize`/`u64` fixes (the target is not declared; one fuzz-reach label is not hit there).
- **2026-10-14** — New `DynModint.sqrt(a, out) bool`: constant-time (in `a`) square root modulo a public prime (`p ≡ 3 mod 4`, Atkin for `5 mod 8`, fixed-trip Tonelli-Shanks otherwise); verified before `true`. KATs from CPython (`tools/gen_sqrt_kat.py`), property test, fuzz harness `montint-dyn-sqrt`, ctgrind `dyn` sqrt row.
- **2026-10-14** — perf: 8-row block Montgomery kernels `asm_core.montMulBlock`/`montSqrBlock` (accumulator window in r8–r15, chunk loop, blocked REDC; dedicated square at every `L`, 4096-bit included), dispatched by `Modint.montMul`/`montSqr` for `L % 8 == 0`, `L >= 16`; `condSubFixed` in asm (was ~25 % of a square at L = 16 in Zig), accumulators zeroed/wiped by vector asm stores (Zig 0.16 lowers `@memset` of a few hundred bytes to a byte-wise `compiler_rt` call), `powMont`'s gather on register-resident 256-bit lanes, and `DynModint.reduceLimbs`/`reduceBytesBE` Horner over whole `L`-limb digits (4 multiplies instead of 64 for a 2048→1024-bit reduction; every Montgomery multiply here is exact for `a < R, b < m`, now stated in SPEC). `bench-montint` vs OpenSSL 3.5.5 BN: 1.08–1.50× → 0.90–1.02×. **Removed fields** `DynModint.digit_bits`/`digit_mont` (internal reducer state; only ctgrind harnesses named them — rsa, blindrsa, jwt, paillier updated). Differential vs the portable CIOS at L = 16..64 incl. all-ones moduli; asm `condSubFixed` vs the Zig form at the decision edges; ctgrind montint rows unchanged in count (digests re-pinned).
- **2026-10-14** — New element predicates: `DynModint.isOdd`, `isOne`, `one`, constant-time `compare` (two borrow chains over the whole slot), and `Modint.eql`, `isZero`, `neg` (Montgomery values are fully reduced, so equality on them is equality of the values). Model-tested against `std.math.big` on edge and random elements; ctgrind `dyn` drives the new ones.

- **2026-10-11** — New `DynModint.fromLimbsPublic` / `fromBytesBEPublic` for a PUBLIC modulus (an RSA `n`): same checks and the same constants bit for bit as `fromLimbs`, built faster — `R mod m` starts at `2^(bits−1)` (new `Modint.fromElemUncheckedBits`) instead of 1, `64·L − bits + 1` doublings instead of `64·L`, one for a full-width 2048-bit modulus. The work depends on the exact bit length, so it is never used for a secret prime: `fromLimbs`/`fromLimbsBits` (CRT primes, Paillier) are unchanged. Tests: `fromLimbsPublic` vs `fromLimbs` on every field for bit lengths 2…4096; `fromElemUncheckedBits` vs the from-1 derivation for every bit length of the 4-, 8- and 32-limb slots.
- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-montint`, kept instrument kind 3): card Performance 1.08–1.54× OpenSSL BN (mul, CT and public modexp, 1024–4096 bit), measured on a quiet host. Tooling only, no code change.

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

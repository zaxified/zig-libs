# montint — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
  `scripts/ctgrind.sh` measures. (c) `blackBox`'s `@inComptime()` guard is now
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
  module's `blackBox` optimization barrier, and `scripts/ctgrind.sh montint`
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

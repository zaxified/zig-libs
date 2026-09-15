# hqc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE, every KEM operation roughly twice as fast:** the
  CLMUL ring multiply in `gf2x.zig` (A1 M4). The Karatsuba base-case leaf carries each partial
  product's high limb into the next word, one store per limb per row. It used to `@memset` its
  output and then XOR-store two limbs per product. The recursion is now specialised on the
  comptime limb count. Same partial products in the same order, bit-identical: a new limb-level
  differential runs against a bit-at-a-time reference at every length 1..33 and at the three ring
  sizes, with the output pre-filled with junk. Measured in one binary, 9 interleaved rounds,
  ReleaseFast: hqc-128 keypair/encaps/decaps −52/−55/−49 %, hqc-192 −55/−59/−57 %, hqc-256
  −60/−60/−58 %. Timed and NOT taken: other `karatsuba_base` values (−1 to −5 %, inside the
  noise) and an xmm-accumulated leaf (−33 to −49 % on its own, but 2-4 % slower than the carry
  leaf once the zeroing is gone). Control flow still depends only on public, comptime lengths.

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** new opt-in profiling workload in `bench.zig`
  (`HQC_PROFILE=1`, skipped otherwise), for A1 M4. keypair, encaps and decaps each loop 4000 times
  inside their own `noinline` wrapper, so a sampling profile can attribute time per operation
  even though ReleaseFast inlines everything beneath. It is driven by `scripts/vm/run.sh hqc`:
  ReleaseFast, `-mcpu native` (so the `pclmul` path is the one profiled), under `perf record` as
  root in the guest. Not in any ctgrind pattern.

- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** `gf2x.zig`'s internal `reduceProduct`
  (the mod-`(X^n-1)` fold at the end of every ring multiply) now folds the extended
  product a `u64` word at a time instead of one bit at a time (A1 M3). Bit-for-bit
  equivalent (new differential test against the original algorithm, kept as a test-only
  oracle) and ~15-17% faster per KEM operation on hqc-128 (measured, see `A1/hqc.md`'s
  M3 disposition). Private function, no signature or behavior a caller can observe.

- **2026-09-09** — **Constant-time fix (3/3): two more masks the compiler had undone.** `reedsolomon`'s `maskNonzero` (the reference's `-(int32_t)x >> 31` trick) and Berlekamp-Massey's `mask12` are laundered through an inline-asm barrier. Both were written branch-free and both were compiled back to branches — 3 measured contexts, at `computeErrorValues` (`x` = `err[i]`) and inside `computeElp`. The barrier sits INSIDE `maskNonzero` rather than at the two call sites that branch today, because `fss` showed one inline function compiling both ways in a single binary. ⭐ `decaps` in-file contexts **5 → 2**; these three cost nothing measurable (bench inside the previous spread), so the +7.3% recorded above is the `gf256` algorithm swap alone. ⭐⭐ **Everything now remaining, in every target, is `sampleFixedWeightRejection`** (`prng.zig:216` the rejection loop, `:223` the accept decision). ⛔ Deliberately NOT masked: the leak is the enclosing loop's trip count, so masking `:223` would remove the memcheck context and leave the timing signal — a prettier measurement of the same defect. Spec v5.0.0 §3.5 requires that sampler for keygen's `x`/`y`; see SPEC.md.

- **2026-09-09** — **Constant-time fix (2/2).** `sampleFixedWeightBiased`'s duplicate-fixup pass blends under an arithmetic mask instead of `if (found) support[idx] = idx`. The scan was already early-exit-free, but the DECISION still branched on `found`, which is derived from the secret support — 3 measured contexts. Same value written, no branch taken. ⭐ With this and the `gf256` change, `encaps` reaches **0 in-file contexts** and `decaps` **14 → 5**. ⛔ The 5 that remain are by design, not oversight: 3 in `reedsolomon` (Berlekamp-Massey's discrepancy test, and `encode` on the re-encryption path) and 2 in `prng` — the rejection loop's trip count, which spec v5.0.0 §3.5 REQUIRES for keygen's `x`/`y`, and `decaps` re-derives `y` from `seed_dk` on every call because the spec fixes a seed-sized `dkKEM`. Sampling `y` the cheap way would produce a different key from the same seed and stop being HQC v5.0.0; it is recorded in SPEC.md rather than silently fixed.

- **2026-09-09** — **Constant-time fix, with a measured cost.** `gf256.mul` and `gf256.inverse` no longer index the `exp`/`log` tables. `mul` is now the reference's own carryless multiply plus fixed-tap reduction (eight masked shift-and-xor steps, then eight masked folds); `inverse` is `a^254` by square-and-multiply over a compile-time exponent. ⛔⛔ The old form indexed a 256-entry table with a SECRET byte, so the cache line touched depended on the operand — the AES T-table class, and measured as such: four memcheck contexts at the old `gf256.zig:114` reported as `Use of uninitialised value` at the LOAD, a different and worse kind than the `Conditional jump` everything else here produces. The module doc defended the table choice as byte-exact, and byte-exact it was — equivalence is about the VALUE, and what differed was the ACCESS PATTERN, which no test comparing outputs can see. ⭐ `decaps` in-file contexts **14 → 8**, `encaps` **6 → 3**, and NO context of the load kind remains anywhere in the module. ⚠ **Costs +7.3% on `decaps` and +1.0% on `encaps`** (3 baseline and 6 post runs, spreads disjoint). ⭐ Equivalence is proven exhaustively, not argued: a new test checks all 65536 `mul` pairs and all 256 `inverse` inputs against the table method, which stays in the file because `reedsolomon.zig` indexes it at PUBLIC positions. ⛔ NOT fixed by this change: `reedsolomon.zig:680/683` index `log` with a secret value, and `prng`'s rejection sampling still branches on secret-derived data (5 contexts).

- **2026-09-09** — Docs: `NOTICE` said "no third-party source was ported" and contradicted
  itself 80 lines later, where it says the two decode cores are "exact ports of the
  reference's `reed_solomon_decode`/`reed_muller_decode`/`fft.c`". Four source files agree
  with the second version; the summary was simply wrong. Corrected, and the upstream's
  terms are now REPRODUCED rather than cited — `gitlab.com/pqc-hqc/hqc` tag `v5.0.0` is
  released into the public domain, re-verified by download 2026-09-09, and the file's own
  hedge about incorporated FIPS202 code ("BELIEVED to be in the public domain") is quoted
  rather than trimmed.

  ⭐ The kind stays `provenance note`, which DIVERGES from what the audit recommended. The
  first line of a NOTICE declares whether a CONDITION travels, and none does: a public-domain
  upstream owes a consumer nothing, so tagging it `third-party attribution` would make the
  one line readers are told to trust less true, and would drag the file under
  `check-copyleft` for no reason. The defect was two false sentences, not the kind.

  ⛔ Also corrected: a heading called all three vendored KAT files "Test-vector oracles".
  Only `src/kat_vectors_code.zig` is — the reference C was compiled and RUN. `kat_vectors.zig`
  and `kat_vectors_kem.zig` are files READ out of the upstream repository, which root
  `NOTICE` §0 separates explicitly. Nothing is owed either way here, but mislabelling read
  data as oracle output is how a module with a non-public-domain upstream quietly exempts
  itself.

  No code or data changed.
- **2026-09-09** — Security fix: `prng.writeSupportToVector`'s mask is laundered through
  an `asm volatile ("" : "+r" (mask))` barrier. The scatter was written branch-free — a
  masked select with no `if` in the source — and LLVM recognised the identity and rewrote
  it back into a branch that loads `bit_tab[k]` only on the taken path, over the long-term
  secret vector, on every decapsulation. Measured with ctgrind (memcheck, taint = the
  decapsulation key), that one loop was **38 of `decaps`'s 52** secret-dependent branch
  contexts. Post-fix, ReleaseFast in-file contexts: `decaps` **52 → 14**, `keygen`
  **26 → 4**, `encaps` **33 → 6**; `sampler` stays at 2, which is the expected result
  since that target never reaches the scatter. `scripts/ctgrind-expected.tsv` is re-pinned
  to the new counts, so deleting the barrier turns `ctgrind --check` red rather than
  passing quietly.

  **No value changed.** Two independent checks: the KAT suite passes byte-exact in Debug,
  ReleaseSafe and ReleaseFast, and the ctgrind table's output pin (`out_sha`, the
  harness's own printed bytes) is unchanged for all four targets.

  **Cost, measured before the fix was applied** — min of 200 calls, ReleaseFast
  `-Dcpu=native`, three alternating runs per arm, spread inside each arm ≤1 %: `keypair`
  +6.9 %, `encaps` +8.4 %, `decaps` +6.2 %. New `src/bench.zig` (opt in with `HQC_BENCH=1`)
  exists to re-derive those numbers; it was written for this measurement rather than
  after it.

  ⚠ NOT fixed by this, and still recorded: `gf256.zig:113/114` branch on secret field
  elements in the GF(256) multiply, the rejection loop compares at `prng.zig:216/223/268`,
  and ReleaseSafe remains far worse than ReleaseFast (`decaps` 92 against 14, down from
  130) because `reedmuller.decodeSymbol`'s overflow checks become branches on
  secret-derived data. See `SPEC.md`.
- **2026-09-08** — The constant-time posture is measured now, and the measurement
  disagrees with what `SPEC.md` claimed. `src/ctgrind_harness.zig` is committed and
  `scripts/ctgrind.sh` drives it; the four rows in `scripts/ctgrind-expected.tsv` are a
  **recorded defect**, not a clean claim. ReleaseFast, tainting the secret half of the
  decapsulation key: `decaps` **52** in-file contexts, `keygen` 26, `encaps` 33, `sampler` 2,
  with the untainted control and the no-`-fvalgrind` trap at 0 for every one. 38 of the 52
  are `writeSupportToVector` — a masked select with no `if` in the source that LLVM rewrites
  back into a branch loading `bit_tab[k]` only on the taken path, adjudicated in the
  disassembly as real jumps. The rest are the GF(256) multiply's `if (a == 0 or b == 0)` and
  `if (s >= 255)`, and the sampler's rejection comparisons. Worse in ReleaseSafe (130), which
  is the mode a cautious consumer deploys. ⭐ A candidate fix is measured and NOT applied
  here: one `asm volatile ("" : "+r" (mask))` barrier takes `decaps` to 14, `keygen` to 4 and
  `encaps` to 6 — it changes crypto code and owes its own KAT and performance evidence.

- **2026-08-14** — Test-only: `kem_kat_test.zig` gained a `testing.fuzz` harness
  on `Hqc128.decaps` (arbitrary ciphertext bytes against a fixed keypair,
  driving the Reed-Muller/Reed-Solomon decode path) — `zig build check-fuzz`
  no longer names this module. No panic/OOB found; **neither breaking nor
  behavioural**.
- **2026-07-21** — Verification: an independent external anchor for the
  Reed-Solomon corrector (constant-time Berlekamp-Massey → Gao-Mateer
  additive-FFT root-finding → Forney), which until now was validated only
  by self-consistent round-trips. Adds an independent syndrome oracle
  (`S_i = Σ c_j·α^{(i+1)j}`, computed separately from the module's own
  `computeSyndromes`) plus four tests: independent-syndrome validity
  (all three parameter sets), a closed-form single-error Peterson anchor
  (recovers an injected position/value by textbook formulas — a different
  construction than BM/FFT/Forney), a delta-capacity positive control
  (exactly δ errors, confirmed RED for a neutered decode before this
  landed), and a beyond-capacity determinism check. No production code
  changed; test-only.
- **2026-07-19** — **Performance: `gf2x.mul` is CLMUL+Karatsuba, not
  schoolbook, ~22-42x faster on `encaps`/`decaps`.** The portable
  shift-and-mask-xor multiply (`mulPortable`, O(n²/64)) is now the
  fallback for non-x86_64/non-pclmul targets and the correctness oracle a
  differential test pins the new path against; on every x86_64+pclmul
  host (i.e. what this module actually ships on) `mul` dispatches to a
  recursive Karatsuba multiply over a `pclmulqdq`-based 64×64→127-bit
  carryless base multiply. Bit-for-bit identical output (KAT suite
  unchanged, plus the new differential test). ⚠ **This entry was missing
  until 2026-09-10** (audit A1 finding `hqc` L5) — `SPEC.md` also
  described only the old schoolbook path for seven weeks after this
  landed; both are corrected together, see `SPEC.md`'s "Design" section.
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Byte-exact
  vs official NIST v5.0.0 `.rsp` (`kat_vectors_kem.zig`, curl-fetched from `pqc-hqc/hqc`
  tag v5.0.0, first 3 counts/set), pk/sk/ct/ss all asserted + decaps.
- **2026-07-16** — New module: HQC (Hamming Quasi-Cyclic) — the code-based KEM NIST
  selected March 2025 as a structurally-independent backup to lattice-based ML-KEM.

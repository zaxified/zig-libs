# hqc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Byte-exact
  vs official NIST v5.0.0 `.rsp` (`kat_vectors_kem.zig`, curl-fetched from `pqc-hqc/hqc`
  tag v5.0.0, first 3 counts/set), pk/sk/ct/ss all asserted + decaps.
- **2026-07-16** — New module: HQC (Hamming Quasi-Cyclic) — the code-based KEM NIST
  selected March 2025 as a structurally-independent backup to lattice-based ML-KEM.

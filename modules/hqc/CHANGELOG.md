# hqc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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

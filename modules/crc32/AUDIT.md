# `crc32` — audit record

The dated reviews and mutation runs of this module, newest first: what was read, which mutants ran, why each
survivor is equivalent, what was found and fixed. The current score is the `**Audit:**` line of the card in
[`SPEC.md`](SPEC.md); this file is the evidence behind it. A new run adds a section at the top; old sections are
not rewritten (a later run supersedes them, it does not edit them).

## 2026-10-03 — review and mutation run

Reviewed `src/root.zig` whole (722 lines): the GF(2) arithmetic (`multModP`,
`xPowShifted`, the `x2n` period-32 indexing), slicing-by-8, the PCLMUL kernel's
slice bounds at every threshold (32, 48, 64, 16-byte tail), the ARMv8 three-way
split and its tail steps, dispatch and the atomic cache, and the table/constant
derivations against the module's own comments and zlib's documented
`crc32_combine`. No defect found; no constant-time claim is made. INFO only:
`multModP(0, b)` would loop forever, unreachable because every first argument is
a power of x (never 0); the dispatch test compared `cpuidPclmul` with itself
and `.table` availability was never asserted (both fixed below).

Mutation run (schemata, ReleaseSafe; 53 mutants on x86-64 built `-mcpu=x86_64`
so that run-time dispatch is live, 12 more on the ARMv8 path built
`-target aarch64-linux -mcpu=generic` and run under `qemu-aarch64 -cpu max`):
**65 mutants, 54 killed, 9 equivalent, 2 real (killed after the fix)**.
Covered: `multModP` start bit, early exit, reduction and add; `x2n` indexing,
`xPowShifted` start/stride, the unit exponents of `xPow8n`/`xPow`; every
slicing-by-8 table index and the tail; `zeros4`; the kernel's `pclmul_min`,
every length threshold, seed XOR, fold constants and their pairing, the
immediates, the reduction steps and tail; dispatch cache, CPUID bit,
`available`, `hashWith`, `extend`, `Crc32.update`, `combine`; the ARM stream
joins, thresholds, tail steps and HWCAP bit. Not mutated: the comptime constant
tables (`x2n` seed, `fold_consts` exponents, `tables`), which tests recompute
bit by bit.

Equivalent:
- `pclmul_min` 33, and 16 (the kernel is correct from 16 bytes; 32 is a speed
  threshold only).
- Slicing loop `>= 9` instead of `>= 8`; kernel lanes `>= 49` instead of `>= 48`,
  fold loop `>= 65` instead of `>= 64`, one-lane loop `> 16` instead of `>= 16`;
  ARM `>= 3 * n` as `> 3 * n`: each only moves the last full block to the next,
  slower loop or to the table tail, which yields the same register.
- `available(.armv8)` as `arch == .aarch64 or backend() == .armv8`, and
  `available(.pclmul)` with `or`: on the machine that runs them both sides agree
  (they differ only on a CPU lacking the feature, which this lane cannot supply).

Real survivors, now killed:
- `available(.table)` false: every comparison test skips an unavailable backend,
  so `.table` silently left all of them. Test `the table backend is always
  available and gives the catalogue value`.
- `cpuidPclmul` reading another bit: the dispatch test compared detection with
  itself. Test `run-time detection agrees with the kernel's CPU flags` (reads
  `/proc/cpuinfo`; skips where unreadable).

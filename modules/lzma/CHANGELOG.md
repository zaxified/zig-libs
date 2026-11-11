# `lzma` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-11** — **NO CONSUMER-VISIBLE CHANGE:** `tools/interop.zig` runs its checks in one shard per CPU (at most 8), each its own process and scratch directory, and adds their counts up; `--capture` stays in one process. Mutants draw from a generator per (shape, base) unit. `zig build interop-lzma` ~300 s → 72 s on 8 CPUs, same 8390 checks.
- **2026-11-01** — **NO CONSUMER-VISIBLE CHANGE:** whole-module mutation audit (568 mutants, 498 killed, 52 equivalent, 18 open, no bug lead) with two new test files; blind-review LOW fixes: the decoder asm is LLVM-only (the self-hosted backend takes the Zig path), a ring the size of the output no longer wraps (a corrupt over-long block now fails at the ring's end instead of at the block size check).
- **2026-10-31** — **Performance:** the decoder is 0.92–1.02× liblzma 5.8.1 (was 1.19–1.27×): liblzma's x86-64 bit-tree / matched-literal / direct-bit assembly, the refill as a plain branch, a dictionary ring 16 bytes longer than its window so match copies need no length branch, and a PCLMULQDQ CRC-64 (`src/crc64.zig`, run-time CPUID) for the `.xz` check. Verdicts and output unchanged (goldens, fuzz, `interop-lzma --decoder` 7541 checks); the ring allocation grows by 32 bytes. No API change.
- **2026-10-31** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the § GZ sweep (20 mutants over the sweep diff, ReleaseSafe schemata): 19 killed, 1 equivalent (the `want == 0` CorruptData boundary: a full ring is reached only after the segment ended or the cap was passed); 2 new tests in `src/sweep_test.zig` (toBytes lc + lp summed wide; the room left under `max_output` caps a stored-chunk read). Not a whole-module mutation score.
- **2026-10-31** — **API change:** `Options.max_output` is `?u64` with a 256 MiB default (`default_max_output`, like bzip2 and brotli; `null` = no cap) for the one-shot and the streaming decoder — a 1 KiB bomb no longer grows `decompress`'s output without bound. **Fixes (no-panic sweep § GZ):** the encoder's match-finder offset no longer overflows after 4 GiB of input (panic in safe builds, UB in ReleaseFast); `StreamWriter.finish()` twice or a write after a failed finish no longer hits an invalid `@errorCast` (`StreamWriter.err` gains `AlreadyFinished`); `preset(level > 9)` clamps to 9 (was assert + out-of-bounds read). `Lzma1Props.toBytes` with out-of-range props and a decoder given a zero-capacity streaming reader are documented checked panics (were overflow / a std assert). The decoder itself had no crash path (sweep + blind review).
- **2026-10-27** — **Performance (fix):** `FastSrc.peek` is `pub` again in effect: `normSel` asks `@hasDecl(@TypeOf(src.*), "peek")`, which since Zig 0.17 sees only `pub` declarations, so the branch-free refill had been dead code since the 0.17 migration (same class as brotli's `tailPtr`, found the same day). No API change.
- **2026-10-23** — **Fix (performance):** `DecompressReader` refills its buffer on small reads. Zig 0.17's `defaultReadVec` streams straight into the caller's slice once the buffer has been filled to its end, so every later small `readSlice*` re-entered the decoder for that many octets. Regression test with a negative control. No API change.

- **2026-10-20** — Independent review (no HIGH): `compressBound` now holds for raw LZMA1 and `.lzma`
  (incompressible input grows ~1.4 %; the old bound allowed 0.1 %), `Format.lzma1` props are range-checked
  (`error.BadHeader`; hand-built props bypassed `fromBytes`), `max_dict` caps the allocated ring (a small
  entry with a huge declared dictionary decodes, as in liblzma), `Encoder.write`/`finish` after `finish`
  return `error.AlreadyFinished`.
- **2026-10-20** — lzma decoder speed: bit trees preload both child probabilities, direct bits and probability updates are branchless, matches are copied by size class, the input cursor is a pointer; decode rows 1.37–1.57× → 1.19–1.27× liblzma. Output unchanged (goldens, fuzz, interop).
- **2026-10-20** — New module: lzma (LZMA1, LZMA2, `.xz`, `.lzma`; for ZIP methods 14 and 95). A
  compressor for presets 0..9 / `-e` and any lc/lp/pb, dictionary, mode, finder, nice length and
  depth that emits, byte for byte, what liblzma 5.8.1 emits (checked against liblzma over 32 input
  shapes in `.xz`, `.lzma`, raw LZMA1 and raw LZMA2; `tools/interop.zig`), `compress` /
  `compressInto` / `StreamWriter` / `Encoder`; a streaming decompressor (`decompress`,
  `decompressStream`, `DecompressReader`) for all four framings with CRC-32 / CRC-64 / SHA-256
  checks, concatenated streams, typed errors and `max_dict` / `max_output` caps, verdict- and
  output-identical to liblzma on 6 000 mutated streams. BCJ and delta filters are refused by name.

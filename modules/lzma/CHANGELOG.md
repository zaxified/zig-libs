# `lzma` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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

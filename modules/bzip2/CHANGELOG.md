# `bzip2` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-20** — New module: bzip2 (.bz2, and the raw stream ZIP method 12 carries). A
  compressor for levels 1..9 that emits, byte for byte, what libbzip2 1.0.8 emits (checked
  against libbzip2 over 36 input shapes, every level, work factors 1/30/100 and CLI-style
  chunking; `tools/interop.zig`), `compress` / `compressInto` / `StreamWriter`; a streaming
  decompressor (`decompress`, `decompressStream`, `DecompressReader`) for concatenated
  streams with block and stream CRCs, randomised blocks, typed errors and a `max_output` bomb
  cap, memory bounded by one block.

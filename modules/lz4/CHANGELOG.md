# `lz4` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-17** — **NO CONSUMER-VISIBLE CHANGE:** the frame fuzz harness draws its mutation positions full-range (`check-fuzz-reach` R2); README Libraries table regenerated for the new module.
- **2026-11-17** — **NO CONSUMER-VISIBLE CHANGE:** whole-module mutation run (109 mutants: 97 killed, 11 equivalent, 1 unobservable); tests added for its survivors and for the cap at exactly one block maximum, a declared size over what is left of the cap, content checksums of concatenated frames, the legacy block size bound, the 13-byte minimum and the 64 KiB window edge, and acceleration.
- **2026-11-17** — New module: lz4, the LZ4 block format and the LZ4 frame format (`.lz4`).
  `decompress` reads LZ4 frames (checksums, content size, linked/independent blocks, every block
  size), skippable and legacy frames, concatenated, with a `max_output` bomb cap; `compress` /
  `compressInto` write one frame (liblz4's defaults); `compressBlock` / `decompressBlock` for raw
  blocks. Checked live against the lz4 1.10.0 CLI and liblz4 through python-lz4
  (`tools/interop.zig`), and on ten frames the CLI wrote (`src/testdata/`).

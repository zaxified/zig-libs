# `lz4` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-17** — New module: lz4, the LZ4 block format and the LZ4 frame format (`.lz4`).
  `decompress` reads LZ4 frames (checksums, content size, linked/independent blocks, every block
  size), skippable and legacy frames, concatenated, with a `max_output` bomb cap; `compress` /
  `compressInto` write one frame (liblz4's defaults); `compressBlock` / `decompressBlock` for raw
  blocks. Checked live against the lz4 1.10.0 CLI and liblz4 through python-lz4
  (`tools/interop.zig`), and on ten frames the CLI wrote (`src/testdata/`).

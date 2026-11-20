# `lz4` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-17** — **NO CONSUMER-VISIBLE CHANGE:** the decoder's fast loop drops an output-room check its loop condition already makes (delta mutation showed it redundant).
- **2026-11-17** — Speed (SPEC Backlog B4), liblz4 1.10's `lz4.c` as the design reference, no code copied. Decoder: a fast loop while the input and the output are far from their ends (16-byte literal and match chunks, a 16-byte pattern for offsets below 16, no call and no error path), which hands any sequence it cannot take with its margins — malformed or near an end — back to the exact tail loop from that sequence's token, so every verdict and byte is the tail loop's. Compressor: a single block under 64 KiB + 11 bytes uses liblz4's `byU16` layout (8192 u16 positions in the same 16 KiB), the next probe's hash is read before the current one is judged, a sequence is written without per-byte room checks when the room left holds its worst case, literals are copied in 8/16-byte chunks without `memcpy`. Behaviour change: `compressBlock` output bytes for inputs under 65547 bytes differ (now the same sizes as `lz4 -1` on the bench payloads); frames are byte-identical to before. `tools/bench.zig` reports the median and the spread of its rounds and has an untimed `ours c|d` mode for instruction counts.
- **2026-11-17** — Behaviour change: after a legacy frame's blocks, a word over `LZ4_COMPRESSBOUND(8 MiB)` ends the legacy frame and is read again as the next magic number, as the lz4 CLI does; junk there is now `error.TrailingData` (ignored with `ignore_trailing_garbage`) instead of `error.BlockTooLarge`. Match lengths are summed with an overflow check from their 4-byte minimum on (no wrap on 32-bit targets). The frame fuzz harness judges `decompress` and `decompressInto` against `modelFrames`, a frame-format model written apart from `frame.zig`, instead of each other. Docs: `multi_frame = false` makes anything after the first frame `TrailingData` (python-lz4 = with `ignore_trailing_garbage`); `acceleration` is `LZ4_compress_fast`'s, liblz4's frame level L maps to `1 - L`; independent blocks start without history (a test decodes each block alone). From an independent review.
- **2026-11-17** — `decompressInto(src, dst, opts)`: the frame decoder into a caller's buffer (SPEC Backlog B5). `dst.len` caps the output like `max_output` (the smaller applies; past it `error.OutputTooLarge`, a declared content size over it refused before decoding); nothing is allocated. Tests for a buffer one byte short, exact and larger, and the fuzz harness checks it against `decompress` under the same cap on every input.
- **2026-11-17** — New module: lz4, the LZ4 block format and the LZ4 frame format (`.lz4`).
  `decompress` reads LZ4 frames (checksums, content size, linked/independent blocks, every block
  size), skippable and legacy frames, concatenated, with a `max_output` bomb cap; `compress` /
  `compressInto` write one frame (liblz4's defaults); `compressBlock` / `decompressBlock` for raw
  blocks. Checked live against the lz4 1.10.0 CLI and liblz4 through python-lz4
  (`tools/interop.zig`), and on ten frames the CLI wrote (`src/testdata/`).

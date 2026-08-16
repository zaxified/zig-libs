# `qrscan` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-17** — New module: locate a QR symbol in a grayscale image and sample
  it into a `qr.Matrix`. Luma plus an explicit `stride` is the input, because the
  two real sources — a V4L2 Y plane and a browser canvas — differ in exactly that
  way, and `lumaFromRgba` bridges the second. Allocation-free over a caller-owned
  scratch buffer, so it runs on a device and in wasm32.
  Three defects worth recording, all found by making the tests reproduce what a
  capture actually looks like rather than by reading the code: candidate finders
  were merged with a running halving, which weights the last row that saw them
  and dragged every centre down by half a finder; the best three candidates were
  taken as the first three, so one false positive inside the data region ruined
  an otherwise perfect read; and the cross product deciding top-right from
  bottom-left had its sign inverted, which transposes the symbol into a grid that
  samples cleanly and decodes to nothing. Steep rotation and perspective are
  documented limits, not oversights.

# `qrscan` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-17** — Rotation at any angle. The module shipped a documented limit
  of "about ten degrees", attributed to `confirmVertical` walking a strictly
  vertical column. That attribution was wrong, and measuring instead of reading
  is what showed it: finders are located at 45° perfectly well, because a line
  through the centre of a square crosses every concentric ring in proportion at
  any angle. What breaks is the **length** the same scan reports — a chord across
  a square tilted by `t` is `side / cos(t)`, so at 45° every module measures 1.41
  pixels too wide, the version comes out four sizes off, and the symbol is
  unreadable with the finders, the triple score and the sampling all looking
  correct. `orient` now takes the tilt from the top edge and corrects for it,
  using each finder's largest scan-line unit rather than its mean, since only the
  chord through the centre has a length the tilt determines.
  Two further limits surfaced behind that one. The candidate list held sixteen
  finders, which a rotated version 13 overflows with false positives from its own
  data region before the third real finder is reached — the symbol was then
  missed for want of a slot; it holds sixty-four now. And the dimension was
  trusted rather than checked, so a module estimate half a percent out produced a
  perfectly-sampled grid of the wrong size, reported by `qr.decode` as a format
  error that reads like a problem with the picture; the neighbouring legal sizes
  are now sampled too and scored on the timing patterns.
  Measured across five versions × three module scales × 5° steps, this reads at
  every angle up to version 24. Version 37 at 3 pixels per module is the
  remaining wall, at about 40 %, and it is an alignment-pattern problem rather
  than a rotation one.
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
  samples cleanly and decodes to nothing. Perspective is a documented limit, not an
  oversight.

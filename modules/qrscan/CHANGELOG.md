# `qrscan` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-17** — Two things that were the same thing. Finders are now located
  with **connected components**: each row's dark runs are labelled as the scan
  goes, and a candidate is required to be a *ring* — the outer band either side
  of the centre one region, joined where the scan line cannot see it. A fence, a
  line of text and a symbol's own data region are three separate regions, so the
  test throws away nearly everything the ratio alone accepts, and it needs no
  second scan line to be intact, which a scratched finder may not have. Labelling
  is by runs rather than pixels — a label per pixel would be 16x this module's
  whole scratch buffer, a row of runs plus a union-find is a few kilobytes.
  And the grid is now **fitted by least squares to every alignment pattern it can
  find**, not just to the three finder corners. Three points fix an affine map
  exactly, which sounds sufficient and is the problem: every error in them lands
  undiluted in the map and is extrapolated across the symbol, so at version 37
  the far corner is 158 modules away and half a pixel becomes half a module.
  Together: a rotated version 37 at 3 pixels per module went from **9 of 72
  angles to 68**, and version 24 at 4 pixels from 4 of 72 to 71. The small end
  moved the other way — a version 1 at 3 pixels went from 63 to 57 — and 3 pixels
  per module is now stated as the floor rather than implied.
  The ring test fails on a small symbol, where a three-pixel light band can be
  welded shut by binarisation, so the whole scan repeats without it when the
  first pass produces nothing readable. Which pass won is settled by asking
  `qr.decode`, because at version 1 the timing patterns are five modules long and
  cannot discriminate; that does not make this a decoder — the caller still gets
  a grid and still has to decode it — it chooses between two grids of our own.
  One defect worth recording: `Fit` takes module indices, `Grid.at` samples
  module centres, and fitting on one while sampling on the other is half a module
  of error **everywhere**. Uniform error leaves the finders, the triple score,
  the dimension and every intermediate value looking correct, and only the decode
  fails.

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

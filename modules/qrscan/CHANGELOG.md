# `qrscan` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Two integer-width defects, both from an audit, both invisible
  to every native test that existed: `linux64`'s `usize` is 64 bits, so nothing
  here could actually wrap on this collection's own runner.
  `scratchSize`/`bitmapBytes`/`blockCount`/`runBytes` computed in plain `usize`,
  which is 32 bits on this module's own declared `.wasm32` target
  (`meta.targets`). A 100,000 x 100,000 image — nothing stopped a caller from
  handing one in, only a `< 21` floor existed — has a true `bitmapBytes` of
  1,250,000,000, which a 32-bit `usize` multiply wraps to 176,258,176 before the
  division that follows it even runs: a buffer about a seventh the size the
  image actually needs, allocated without complaint. Fixed two ways, both
  needed: the arithmetic now runs in `u64` throughout (`u32 * u32` cannot
  overflow it) with the final narrowing to `usize` *saturating* rather than
  wrapping, and `scan` now enforces `max_dimension = 8192` on `width`/`height`
  — chosen as comfortably past the highest resolution either real source (a
  V4L2 camera plane or a browser canvas; 8K/7680x4320 is the current practical
  ceiling for both) produces, while keeping `width * height` 64x below the
  2^32 wrap point and `scratchSize` at that ceiling to about 9.5 MB, a buffer a
  caller can actually allocate. An oversized image now gets `Error.BadImage`
  before any of the arithmetic above runs.
  Separately, `Image.at`'s index computation left `y * stride + x` in `u32`,
  where `Bitmap.get`/`set` deliberately widen to `usize` first — the one path
  through binarisation that did not match the pattern the rest of the module
  uses. On `scan`'s hot path (`binarize`, called from every pixel of every
  scan) that is live on 64-bit targets too, not only `wasm32`: it needs a
  multi-gigabyte real buffer, not a 32-bit `usize`, to actually overflow.
  Fixed by widening the same way `Bitmap.get`/`set` already do; the arithmetic
  was pulled out into a small `Image.index` so it is unit-testable without
  allocating the multi-gigabyte buffer a full repro would otherwise need.
  Tests: the `max_dimension` rejection is target-independent and asserts the
  concrete `Error.BadImage` (and that `max_dimension` itself, not
  `max_dimension - 1`, is the accepted edge); `scratchSize` is checked against
  an independently computed `u64` byte count at the auditor's own
  100,000 x 100,000 case, alongside the literal 176,258,176 a 32-bit `usize`
  would have produced, so the historical defect is pinned as a number rather
  than described; and `Image.index`'s widening is checked directly against a
  `stride`/`y`/`x` combination that overflows `u32` — meaningful on this
  64-bit host, and explicitly not claimed to mean anything if ever executed on
  `.wasm32`, whose 32-bit address space cannot hold the value being checked
  either way. `zig build test-qrscan` (all three release lanes) and
  `zig build portable-qrscan-wasm32` (compile-only — no wasm32 runtime was
  available to execute it) both green.

- **2026-08-17** — Tried and rejected, recorded so it is not tried again:
  reading each module as the majority of the 3x3 neighbourhood around its centre,
  to help the one case still below 100 % — a version 1 at three pixels per
  module. It makes it worse, 31 of 36 angles down to 22, and version 6 from 36 to
  29. At three pixels per module a 3x3 neighbourhood is a whole module wide, so
  it averages in the neighbours. Whatever helps there has to happen in
  binarisation, which is what decides those pixels.
- **2026-08-17** — Off-axis symbols. The grid can now be projective: a plane
  photographed at an angle maps to the image by a homography, and no affine map
  approximates one across a whole symbol. Measured before the change, at six
  pixels per module, a version 13 stopped reading at **0°** of tilt and a
  version 6 at 5°; after, they read to 15–25° depending on the axis. A version 1
  is unchanged at 10°, and always will be — it carries no alignment patterns, so
  there is nothing a projective fit could be built from.
  What made the measurement possible came first: `renderProjective` and
  `renderCylindrical` in the tests, both checked at their own identity against
  the flat renderer. "Perspective is a limitation" had never been measured; it
  was a claim about the shape of the code, which is the kind that was wrong
  about rotation earlier the same day.
  Three defects found on the way, each of which made the fix look ineffective
  rather than broken: the alignment-pattern check bounded the **outer** ring runs
  from above, and an outer ring touching a dark data module reads as two modules
  wide — so a version 2–6 symbol's single alignment pattern was never found and
  the projective fit had nothing to fit. The search widens its window across
  passes, but the loop stopped as soon as a pass found nothing new, which is
  precisely how a too-narrow window fails, so the wider passes never ran. And
  the first fitter alternated between the affine and perspective halves; it
  minimises the right thing and converges, forty rounds getting a fifth of the
  way to what a normalised direct solve gets exactly.
  Also: landmarks the fit cannot account for are dropped rather than averaged
  in, since a widened window over a data region will eventually return a dark
  module that crosses like an alignment pattern. That alone took plain rotation
  at version 37 and three pixels per module from 68 of 72 angles to 72.
  Curvature is not modelled and is not the problem it sounds like: a version 1
  reads wrapped on a cylinder 18 modules across, a version 6 to 45. A mesh over
  the alignment patterns would cover it, and is now the one item in the backlog.

- **2026-08-17** — Nothing beyond 1024 pixels existed. `binarize` kept its
  per-block means in a fixed `[128 x 128]u8` on the stack and clamped its loops
  to it, so only the first 1024 x 1024 pixels of any image were binarised at
  all: the rest of the bitmap was never written, and the finder scan then read
  whatever the caller's scratch buffer already contained. The same symbol read
  at (100, 100) of a 1200 x 1200 frame and was `NotFound` at (1000, 1000) — and
  the module's README opened with a 1920 x 1080 example, so the documented use
  was blind over 47 % of the frame and its bottom 56 rows. The row scanner had
  the same shape of bug at 512 runs per row.
  Both are now sized from the image out of the caller's scratch, so
  `scratchSize` covers the bitmap, the block means (+12.5 %) and two rows of
  runs, and the stack loses 28 KB. Tests size their buffers with `scratchSize`
  instead of open-coding a layout that has now changed twice.
  The test that would have caught it puts a symbol in **each corner** of a
  frame larger than 1024 in both axes, with the scratch pre-filled `0x00` and
  `0xFF` in turn: one position cannot find "a region of the frame is not
  processed", and identical answers from opposite fills is what "no
  uninitialised memory is read" means from outside.

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

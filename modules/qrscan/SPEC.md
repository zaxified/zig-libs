# `qrscan` — design, verification, backlog

## Design & invariants

**Luma plus stride is the seam, and it is chosen by what the sources are.** A
V4L2 capture in NV12/YUV420 has a Y plane that is already 8-bit luminance, with
rows padded to an alignment; a browser canvas has tight RGBA. Taking luma with an
explicit `stride` serves the first natively and the second after
`lumaFromRgba`. An API without `stride` looks equivalent and is unusable on a
camera — that is the detail this design is built around, and there is a test that
lays a symbol into a padded buffer with junk in the padding.

**Allocation-free by construction.** The one working buffer is the binarised
bitmap, sized by `scratchSize` and owned by the caller. This has to hold at 30 fps
on a device with no allocator, and in wasm32 where a static footprint is the
point.

**Binarisation is block-adaptive because a global threshold cannot survive a
real capture.** Every hand-held photograph has a gradient or a shadow across it.
Blocks are 8×8 and each threshold is the average over a 5×5 neighbourhood of
block means, so a block that is entirely inside a finder — flat, no contrast —
inherits its neighbours' threshold instead of inventing one by splitting its own
noise.

**More than three finder candidates is the normal case.** The 1:1:3:1:1 run
occurs inside the data region as well, and vertical confirmation does not always
reject it: a real symbol in the tests produces four. So orientation scores every
triple by how well it forms three corners of a square — equal legs, hypotenuse
√2 times a leg, agreeing module sizes — and takes the best. Taking the first
three is what the first implementation did, and one false positive ruined an
otherwise perfect read.

**The finder centre comes from the vertical extent, not from the row that found
it.** A row-scan hits the same finder on every row it spans; the triggering row
is somewhere inside the pattern, not at its middle. Merging candidates with
`(old + new) / 2` compounds that into a bias toward the last row seen — measured
at roughly half a finder, which is under a module and still moves every sampling
point. Centres come from the confirmed vertical band, and merging uses a counted
mean.

**Image coordinates are left-handed and the cross product reads accordingly.**
With y growing downwards, a *positive* cross product of (p − tl) × (q − tl) means
p is the top-right. Inverted, the symbol is transposed — and a transposed symbol
still samples cleanly and still yields a well-formed grid, so the failure appears
as "decodes to nothing" rather than as anything pointing at orientation.

## Threat model & out of scope

Input is an image someone else chose, so every dimension and every pixel is
untrusted. Bounds are checked before anything is indexed: `luma` must cover
`stride * height`, the scratch must meet `scratchSize`, and each sampling point is
range-checked against the bitmap rather than assumed to land inside it. There is
no allocation, so there is no allocation to exhaust; work is linear in pixels
except the triple search, which is cubic in candidates and therefore capped at 16.

Failing to find a symbol returns `NotFound`. Deciding whether a located symbol is
*readable* is `qr.decode`'s job, and the split matters: a scanner that reports
success for a grid it merely sampled would hide every decode failure behind a
detection success.

## Verification

Tests start from a symbol whose correct answer is known — encoded with `qr`,
rendered to pixels, scanned back — and check the sampled grid **module for
module** against the original, not merely that it decodes. A grid that decodes is
weaker evidence than a grid that is identical, because error correction hides
sampling mistakes up to its capability.

Covered: three texts across three module scales; a padded-stride buffer with junk
in the padding; upright, slightly tilted and quarter-turn rotations; and a
contrast-rich image with no symbol in it, which must return `NotFound` rather
than a guess.

The three defects above were all found this way rather than by reading the code,
which is the argument for rendering the input instead of hand-writing bitmaps.

## Anchoring

**Re-derived.** Expected values come from this repo's own encoder: `qr` produces
a symbol, this module reads it back, and the two grids must agree exactly. That
catches sampling, orientation and binarisation errors, and it does **not** catch
a shared misreading of the standard's geometry — but `qr` itself is anchored
EXTERNAL against an independent encoder and an independent decoder, so the
geometry those grids embody has outside authority even though this module's
comparison is internal.

**Anchor grade:** class B · oracle REDERIVED

## Backlog

- **Rotation-invariant finder location.** The top item. Row-scanning finds the
  bands at any angle, but confirmation walks a strictly vertical column, so past
  roughly ten degrees the ratio no longer holds and candidates are dropped.
  Locating finders as connected components is rotation-invariant by construction
  and is the approach a robust reader takes; it replaces `confirmVertical` rather
  than adjusting it.
- **Perspective correction.** The affine map from three finder centres is exact
  for a flat symbol square to the camera. Off-plane needs the bottom-right
  alignment pattern and a projective map — which also raises the largest version
  that samples accurately, since alignment patterns exist to correct exactly this.
- **Multiple symbols per frame.** Candidates for several are already found; only
  the best triple is sampled. A wallet showing two codes at once is the case.
- **Sub-pixel sampling.** Each module is read from a single pixel at its centre.
  Averaging a small neighbourhood costs little and would help at small module
  sizes, where one noisy pixel currently decides a module.

## Status

`build · any · codec · reentrant` + deps: `qr` — canonical source is
`pub const meta` in `src/root.zig`.

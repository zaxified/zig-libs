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

**How many candidates the list holds is a detection limit, not a memory
setting.** False positives scale with the data region, so a large symbol
produces them faster than the real finders are reached: a rotated version 13
yields more than sixteen candidates, and with a list of sixteen the third real
finder has nowhere to go. The symbol is then missed for want of a slot, which
presents as "not found" with nothing in the picture to blame. Sixty-four covers
every case measured; the cost is the triple search, which is cubic.

**The ratio is rotation-invariant; the length that comes with it is not.** A line
through the centre of a square crosses every concentric ring in proportion at any
angle, which is why finders are located at any rotation — but a horizontal chord
across a square tilted by `t` measures `side / cos(t)`. At 45° that reports 1.41
pixels of module for every one, the version lands four sizes out, and the symbol
is unreadable while the finders, the triple score and the sampling all look
correct. `orient` recovers `t` from the top edge (`tl → tr`, wrapped into ±45°
because a square is unchanged by a quarter turn) and multiplies it back out.
The estimate used is each finder's **largest** scan-line unit rather than its
mean: only the chord through the centre has a length that is a fixed function of
the tilt, and averaging over the rows either side undercuts it by 13 % at 45°.

**The version is checked, not trusted.** A dimension one version out samples
perfectly well — every module gets a value and the grid looks like a QR code —
and `qr.decode` then reports a format error that reads like a problem with the
picture. So the neighbouring legal sizes are sampled too and scored on the timing
patterns, which are the one part of a symbol whose content the standard fixes
rather than the message. Deliberately no minimum score: a real symbol with a
damaged timing pattern still decodes, because the data is protected and the
timing is not, so the score chooses between candidates and does not get a veto.

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
except the triple search, which is cubic in candidates and therefore capped at
64, and the dimension search, which samples at most five grids.

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
in the padding; **two symbols swept through a full turn in 15° steps**; and a
contrast-rich image with no symbol in it, which must return `NotFound` rather
than a guess. The rotation sweep is the regression net, but three tests pin the
mechanisms underneath it individually, because a sweep that goes red says only
that something moved: that the tilt correction turns a 1.41× scan-line estimate
back into the rendered module size, that a dimension one version out is rejected
by its timing pattern, and that a large rotated symbol really does produce more
than sixteen candidates.

A wider sweep than the tests keep — five versions × three module scales × 5°
steps — reads at every angle up to version 24. Version 37 at 3 pixels per module
is where it stops, at about 40 %.

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

- **Sampling accuracy at large versions.** The top item, and what the old
  "rotation-invariant finder location" entry was really pointing at: rotation
  itself is handled, but a rotated version 37 at 3 pixels per module reads about
  40 % of the time. The cause is accumulated error in an affine map fitted to
  three points 158 modules apart, which is precisely what alignment patterns
  exist to correct — so this and perspective correction are the same piece of
  work.
- **Connected-component finder location.** Was assumed to be the fix for
  rotation, and is not: the run-length scan finds finders at every angle already.
  It remains the more robust approach for a *damaged* finder, where a run-length
  scan needs the bands to survive intact along one line, and it would remove the
  candidate-list ceiling. Not scheduled — no measured failure currently points at
  it.
- **Perspective correction.** The affine map from three finder centres is exact
  for a flat symbol square to the camera. Off-plane needs the bottom-right
  alignment pattern and a projective map.
- **Multiple symbols per frame.** Candidates for several are already found; only
  the best triple is sampled. A wallet showing two codes at once is the case.
- **Sub-pixel sampling.** Each module is read from a single pixel at its centre.
  Averaging a small neighbourhood costs little and would help at small module
  sizes, where one noisy pixel currently decides a module.

## Status

`build · any · codec · reentrant` + deps: `qr` — canonical source is
`pub const meta` in `src/root.zig`.

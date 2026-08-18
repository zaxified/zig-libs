# `qrscan`

Find a QR symbol in a grayscale image and sample it into a `qr.Matrix`, which
[`qr`](../qr/README.md) then decodes. No allocator: the caller supplies one
scratch buffer, sized by `scratchSize` — call it rather than working the number
out, since it covers the bitmap, the block means and the labeller's runs, and
what it covers has changed.

```zig
const qrscan = @import("qrscan");
const qr = @import("qr");

var scratch: [qrscan.scratchSize(1920, 1080)]u8 = undefined;
const img: qrscan.Image = .{ .luma = plane, .width = 1920, .height = 1080, .stride = 2048 };

const found = try qrscan.scan(img, &scratch);
var m = found.matrix;
const text = try qr.decode(&m, &out);
```

## Luminance in, not a file

The two sources that exist give different things and neither is a PNG:

| source | format | stride |
|---|---|---|
| V4L2 camera (NV12/YUV420) | **Y plane is already 8-bit luma** | padded — usually wider than the image |
| browser `getImageData()` | RGBA, 4 bytes per pixel | tight (`width * 4`) |

So the input is luma with an explicit `stride`, and `lumaFromRgba` converts the
other one. **`stride` is not optional decoration** — a camera plane's rows are
aligned, and an API that assumes `stride == width` is unusable on a device.

Decoding PNG or JPEG is the caller's job. It belongs to a module about images,
not to one that is otherwise pure arithmetic over a buffer.

## What it does

1. **Block-adaptive binarisation** — 8×8 blocks, each threshold smoothed over its
   neighbours. A global threshold cannot survive a gradient across the frame or a
   shadow across the symbol, which every hand-held capture has.
2. **Finder location** — the 1:1:3:1:1 run scanned along rows, with each row's
   dark runs labelled into connected components as it goes. A finder's outer
   band either side of its centre is **one region**, joined above and below
   where the scan line cannot see; a fence, a line of text and a symbol's own
   data are three separate regions. That test rejects nearly everything the
   ratio alone accepts, and needs no second scan line to be intact — so it
   survives rotation and damage that a column walk does not.
3. **Orientation** — of the candidates, the triple that best forms three corners
   of a square wins.
4. **Sizing** — the module size a scan line measures is inflated by the symbol's
   tilt, so it is corrected before it decides the version, and the version is
   then checked against the timing patterns rather than trusted.
5. **Sampling** — a grid fitted to the three finder centres **and every
   alignment pattern it can find**, affine and projective both, with the timing
   patterns choosing between them. Three points fix an affine map exactly, and
   exactly is the problem: every measurement error in them lands undiluted in
   the map and is then extrapolated across the whole symbol. Two more terms make
   the map projective, which is what a symbol photographed off-axis needs.

If that pass does not produce a readable grid, the scan is repeated without the
connected-region requirement — which is what a small symbol needs, since at
three pixels per module the light band between ring and centre is three pixels
wide and binarisation can weld it shut.

## Rotation

Any angle. The 1:1:3:1:1 ratio is rotation-invariant — a line through the centre
of a square crosses every concentric ring in proportion, whatever the angle — so
finders are located at any rotation. What is *not* invariant is the length that
comes with the ratio: a horizontal chord across a square tilted by `t` measures
`side / cos(t)`, and at 45° that is 1.41 modules reported for every one, which
sets the version four sizes out and reads as a symbol nobody can decode. `orient`
takes the tilt from the top edge and corrects for it.

## Limits, stated plainly

- **Tilt is handled to about 15–25°, not to 60.** A symbol photographed
  off-axis is a projective image and gets a projective grid, fitted to the
  alignment patterns. Measured at six pixels per module: a version 6 reads to
  25° about the vertical axis and 15° about the horizontal, a version 13 to
  15°/20°, a version 1 to 10° — it has no alignment patterns at all, so there is
  nothing a projective fit could be built from. Before there was a projective
  grid, those were 5°, 0° and 10°.
- **Curvature is not modelled**, and matters less than you would think: a
  version 1 still reads wrapped on a cylinder 18 modules across, a version 6
  down to 45 and a version 13 down to 200. A label on a can is fine; a large
  symbol round a small bottle is not. Correcting it needs a mesh over the
  alignment patterns rather than one global map.
- **Three pixels per module is the floor.** There, a version 37 reads at about
  94 % of angles and a version 1 at about 79 %; at four pixels per module both
  are 100 %. Below three, binarisation is deciding modules from single pixels.
- **One symbol per image.** The candidate search finds several, but only the best
  triple is sampled.
- **`width`/`height` above `qrscan.max_dimension` (8192) are refused with
  `Error.BadImage`**, checked before `scratchSize`'s arithmetic ever runs. 8192
  is comfortably past the highest resolution either real source (a V4L2 camera
  plane or a browser canvas) produces today — 8K/7680x4320 is the current
  practical ceiling for both.

Provenance: original work of the zig-libs authors (MIT). Symbol geometry is from
ISO/IEC 18004; the block-adaptive binarisation follows the approach the ZXing
family documents, from that description rather than its source. See
[`SPEC.md`](SPEC.md).

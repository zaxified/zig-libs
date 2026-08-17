# `qrscan`

Find a QR symbol in a grayscale image and sample it into a `qr.Matrix`, which
[`qr`](../qr/README.md) then decodes. No allocator: the caller supplies one
scratch buffer.

```zig
const qrscan = @import("qrscan");
const qr = @import("qr");

var scratch: [1920 * 1080 / 8]u8 = undefined;   // qrscan.scratchSize(w, h)
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
2. **Finder location** — the 1:1:3:1:1 run scanned along rows, then confirmed
   down the column through each candidate. Confirmation is what rejects the
   ordinary five bands that a fence or a line of text produces.
3. **Orientation** — of the candidates, the triple that best forms three corners
   of a square wins. More than three candidates is normal, not exceptional: the
   finder ratio occurs inside the data region too, and the larger the symbol the
   more often, which is why the candidate list holds sixty-four rather than a
   handful.
4. **Sizing** — the module size a scan line measures is inflated by the symbol's
   tilt, so it is corrected before it decides the version, and the version is
   then checked against the timing patterns rather than trusted.
5. **Sampling** — an affine map from the three finder centres, each of which sits
   3.5 modules in from its corner.

## Rotation

Any angle. The 1:1:3:1:1 ratio is rotation-invariant — a line through the centre
of a square crosses every concentric ring in proportion, whatever the angle — so
finders are located at any rotation. What is *not* invariant is the length that
comes with the ratio: a horizontal chord across a square tilted by `t` measures
`side / cos(t)`, and at 45° that is 1.41 modules reported for every one, which
sets the version four sizes out and reads as a symbol nobody can decode. `orient`
takes the tilt from the top edge and corrects for it.

## Limits, stated plainly

- **No perspective correction.** The affine map from three finders is exact for a
  flat, square-on symbol. A symbol photographed at an angle to the plane needs
  the bottom-right alignment pattern and a projective map. The same missing
  refinement is what limits large symbols at small module sizes: a rotated
  version 37 at 3 pixels per module reads about 40 % of the time, because half a
  module of error accumulated over 158 of them is a wrong sample.
- **One symbol per image.** The candidate search finds several, but only the best
  triple is sampled.

Provenance: original work of the zig-libs authors (MIT). Symbol geometry is from
ISO/IEC 18004; the block-adaptive binarisation follows the approach the ZXing
family documents, from that description rather than its source. See
[`SPEC.md`](SPEC.md).

# `qr`

QR Code symbol **encoder and decoder** — ISO/IEC 18004 model 2, versions 1–40,
error-correction levels L/M/Q/H, numeric/alphanumeric/byte modes. No allocator,
no I/O, no syscalls: the caller owns the only buffer.

```zig
const qr = @import("qr");

var m: qr.Matrix = undefined;
try qr.encode(&m, "https://example.com", .{ .ecc = .quartile });
// m.size, m.version, m.mask, m.isDark(x, y)
```

`encode` picks the most compact mode the input allows, the smallest version that
fits, and the mask with the lowest penalty. `Options` forces any of the three
when you need a specific symbol rather than the best one.

## Reading one back

```zig
var out: [4096]u8 = undefined;
const text = try qr.decode(&m, &out);
```

`decode` reads the format information, unmasks, de-interleaves and runs
Reed-Solomon **error correction** — up to the level's declared capability, which
is what makes a scratched or partly obscured symbol still readable. Past that
capability it returns `error.Uncorrectable` rather than a plausible wrong string;
a QR library that confidently returns the wrong URL is worse than one that
declines.

**Input is a matrix, not an image.** Building that matrix from a photograph —
binarisation, locating the symbol, perspective correction, grid sampling — is
image processing, and both mature ecosystems split it out the same way (Rust
pairs an encoder crate with `rqrr`; Go pairs `skip2` with `gozxing`). Use
`Matrix.setDark` to fill a grid your own scanner produced, then call `decode`.

## Rendering

The symbol itself is a grid; two renderers cover the two places one actually
leaves a program.

```zig
try qr.writeSvg(response_writer, &m, .{ .scale = 8 });
try qr.writeTerminal(stdout, &m, .{});
```

Both take a `*std.Io.Writer`, so a program with no allocator can point them at a
`std.Io.Writer.fixed` buffer and one with an allocator at
`std.Io.Writer.Allocating`. Neither can affect what a symbol says — they live in
`render.zig`, nothing in the codec calls them, and the codec has no pixel format
anywhere in it.

**SVG.** Dark modules come out as a single `<path>` of horizontal runs under a
`viewBox` in module units, so `scale` changes the rendered size without changing
any geometry. `SvgOptions` covers the quiet zone, both colours and a `<title>`
for screen readers; every one of those strings is XML-escaped on the way out, so
a title taken from a request body cannot close the element and continue as
markup. `light = null` drops the background rectangle — worth doing only when
the surface behind is known to be light, because a QR code on a dark page does
not scan.

**Terminal.** Two module rows per line via half-block characters, so the symbol
is square in a normal font and scannable off the screen. `dark_background` is
not cosmetic: glyphs are drawn in the foreground colour, so on a dark terminal
the *light* module is the one that gets a glyph. Set it wrong and what is on
screen is a photographic negative, which scanners refuse.

Anything else — PNG, a framebuffer, a print pipeline — is a few lines over
`m.isDark(x, y)` plus `qr.quiet_zone`, which is exported because the number is
the standard's (§6.3.8, four modules on every side) and no renderer should pick
its own.

## Choosing a level and a mode

`Ecc` trades capacity for damage tolerance — the standard's own recovery figures
are roughly 7 % (`.low`), 15 % (`.medium`), 25 % (`.quartile`) and 30 % (`.high`)
of codewords. `.medium` is the default because it is what most printed codes use;
`.quartile` or `.high` earn their cost on anything that will be photographed off
a curved, dirty or badly lit surface.

Mode selection is automatic and purely about density: digits pack 3 per 10 bits,
the 45-character alphanumeric set (`0-9 A-Z` space `$%*+-./:`) packs 2 per 11,
and everything else costs 8 bits per byte. Note that the alphanumeric set is
upper-case only — `"HELLO"` encodes alphanumerically, `"Hello"` falls to byte
mode and needs a larger symbol.

`Options.mode` forces one, and returns `error.ModeMismatch` rather than silently
widening if the input cannot be expressed that way.

## Not implemented

**Kanji mode.** It encodes Shift-JIS double-byte values, so a caller would have
to transcode into that encoding before calling; byte mode carries the same text
as UTF-8 in the same or fewer bits for anything short of near-pure Japanese.

**Structured append** (splitting one message across up to 16 symbols), **ECI**
(declaring a character set other than the default), and **Micro QR**. None are
needed by a caller that wants "put this text in a QR code", and each is a
separable addition rather than something this design forecloses.

**Reading from an image.** `decode` takes a matrix; producing that matrix from a
photograph is binarisation, symbol location, perspective correction and grid
sampling. That is image processing rather than coding, it would drag a pixel
format and a `platform` tag into a module that has neither, and every mature
ecosystem ships it separately.

Provenance: original work of the zig-libs authors (MIT), clean-room from
ISO/IEC 18004. Verification, including the two independent oracles, is in
[`SPEC.md`](SPEC.md).

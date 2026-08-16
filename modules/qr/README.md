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

## The output is a matrix

A QR symbol is a grid of dark and light modules. Rendering it involves choices
that belong to the caller — scale, colours, output format, whether the quiet zone
is drawn or provided by the surrounding page — so the module hands over the grid
and stops. `qr.quiet_zone` is the one rendering-adjacent constant it does export,
because that number comes from the standard (§6.3.8, four modules on every side)
and every renderer needs it.

Both renderers below are complete. That they are this short is the argument for
not shipping them.

**SVG**

```zig
fn writeSvg(m: *const qr.Matrix, w: *std.Io.Writer, scale: u32) !void {
    const q = qr.quiet_zone;
    const side = (m.size + 2 * q) * scale;
    try w.print(
        \\<svg xmlns="http://www.w3.org/2000/svg" width="{d}" height="{d}" shape-rendering="crispEdges">
        \\<rect width="100%" height="100%" fill="#fff"/>
        \\
    , .{ side, side });
    for (0..m.size) |y| {
        for (0..m.size) |x| {
            if (!m.isDark(@intCast(x), @intCast(y))) continue;
            try w.print("<rect x=\"{d}\" y=\"{d}\" width=\"{d}\" height=\"{d}\" fill=\"#000\"/>\n", .{
                (x + q) * scale, (y + q) * scale, scale, scale,
            });
        }
    }
    try w.writeAll("</svg>\n");
}
```

**Terminal** — two rows per line via half-block characters, so the symbol comes
out square in a normal font and stays scannable off the screen.

```zig
fn writeTerminal(m: *const qr.Matrix, w: *std.Io.Writer) !void {
    const q = qr.quiet_zone;
    const n = m.size + 2 * q;
    var y: u16 = 0;
    while (y < n) : (y += 2) {
        for (0..n) |x| {
            const top = inSymbol(m, @intCast(x), y, q);
            const bot = inSymbol(m, @intCast(x), y + 1, q);
            // Inverted: a dark module must print as a light cell on a dark
            // terminal, or scanners read the negative and refuse it.
            try w.writeAll(if (top and bot) " " else if (top) "▄" else if (bot) "▀" else "█");
        }
        try w.writeAll("\n");
    }
}

fn inSymbol(m: *const qr.Matrix, x: u16, y: u16, q: u8) bool {
    if (x < q or y < q or x >= m.size + q or y >= m.size + q) return false;
    return m.isDark(x - q, y - q);
}
```

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

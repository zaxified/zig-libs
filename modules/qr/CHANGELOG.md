# `qr` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-17** — Rendering: `writeSvg` and `writeTerminal`, in a `render.zig`
  the codec does not call. They were previously copy-paste snippets in
  `README.md`, on the argument that being short is a reason not to ship them;
  what changed is consumption — five candidate consumers (a web API, two CLIs, a
  GUI, an agent) would each have pasted them, which is five copies of the two
  details that are easy to get wrong: a dark module has to print as a *light*
  cell on a dark terminal or the symbol on screen is a negative that no scanner
  accepts, and caller-supplied strings in the SVG have to be XML-escaped or a
  title from a request body is markup injection. The SVG is now one `<path>` of
  horizontal runs under a `viewBox` in module units instead of one `<rect>` per
  module. Both renderers are verified by parsing their output back into a grid
  and comparing module for module against the source matrix — rendering and then
  *decoding* would be the weaker test, because error correction hides sampling
  mistakes up to its capability and a transposed rendering still reads correctly.
- **2026-08-17** — Decoding: `decode` takes a matrix and returns the message,
  including Reed-Solomon error *correction* (syndromes → Berlekamp-Massey →
  Chien → Forney), which is the half an encoder never needs. Reaches parity with
  what the mature Rust and Go ecosystems offer, where encoder and decoder are
  almost always separate libraries. Two defects worth recording, both invisible
  to a round-trip test because a clean symbol never enters the correction path:
  the Chien search looked for roots at `alpha^-i` instead of `alpha^-(n-1-i)`,
  which "corrects" a block into something that then fails the syndrome re-check
  and so presents as an uncorrectable symbol rather than as a bug; and
  `Matrix.set` was private, which made `decode` uncallable by the only consumer
  it exists for — a scanner has to be able to BUILD a matrix. It is now
  `Matrix.setDark`. Verified by feeding an independent encoder's matrices to our
  decoder (120 symbols) and by testing correction at exactly the capability
  boundary: eight corrupted codewords in a version 1-H block succeed, nine are
  refused.
- **2026-08-17** — New module: QR Code symbol encoder (ISO/IEC 18004 model 2),
  versions 1–40, levels L/M/Q/H, numeric/alphanumeric/byte modes. Clean-room
  from the standard; no third-party QR implementation was read. Output is the
  module matrix rather than an image.
  Verified against two independent oracles that share no author with this
  module: an encoder, compared byte-for-byte over all 40 versions x 4 levels
  (320 matrices) plus 672 more across masks and inputs, and a decoder, which
  read back all 84 symbols it was given. That comparison found the one defect
  the module's own tests had missed — **version 32's alignment centres are an
  outlier in the standard's table**, not derivable by the spacing rule that
  covers every other version, so they are special-cased with versions 31 and 33
  pinned as derived either side of the exception.

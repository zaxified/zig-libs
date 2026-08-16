# `qr` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-17** — New module: QR Code symbol encoder (ISO/IEC 18004 model 2),
  versions 1–40, levels L/M/Q/H, numeric/alphanumeric/byte modes. Clean-room
  from the standard; no third-party QR implementation was read. Output is the
  module matrix rather than an image — rendering is the caller's choice and
  `README.md` carries complete SVG and terminal renderers to make that cheap.
  Verified against two independent oracles that share no author with this
  module: an encoder, compared byte-for-byte over all 40 versions x 4 levels
  (320 matrices) plus 672 more across masks and inputs, and a decoder, which
  read back all 84 symbols it was given. That comparison found the one defect
  the module's own tests had missed — **version 32's alignment centres are an
  outlier in the standard's table**, not derivable by the spacing rule that
  covers every other version, so they are special-cased with versions 31 and 33
  pinned as derived either side of the exception.

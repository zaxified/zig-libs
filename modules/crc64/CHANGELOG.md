# crc64 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-21** — New module: CRC-64/XZ (the `.xz` check, ECMA-182 reflected) with a PCLMULQDQ folding kernel chosen at run time and a slicing-by-8 fallback, in the shape of `std.hash.crc.@"CRC-64/XZ"` plus `extend`; moved out of `lzma`, which now depends on it. Checked against the `std` CRC-64/XZ at every length and against values liblzma computed.

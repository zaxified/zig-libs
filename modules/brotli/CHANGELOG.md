# brotli — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- The encoder now actually compresses. It was store-mode only (ratio
  ~1.0); it now does LZ77 backward references plus a per-meta-block
  Huffman code for literals, insert-and-copy commands and distances, with
  the store path kept as an automatic per-block fallback whenever a
  compressed block would not come out smaller. `alice29.txt`
  152 089 -> 54 605 bytes (2.8x), between reference `brotli` quality 1 and
  5; incompressible input costs the same as it does the reference.
  `compress` keeps its signature and its "fails only on allocation,
  output is always a valid `br` body" guarantee. Not implemented (each
  costing ratio): block splitting, literal context modelling,
  static-dictionary references, `NPOSTFIX`/`NDIRECT` tuning, and distance
  short codes. Validation is anchored on the reference implementation
  rather than on this module's own decoder: `src/reference_interop.zig`
  decompresses everything the encoder emits with google/brotli (Python
  `brotli`) across a property sweep of input shapes, and skips loudly
  when python3 or the package is missing.

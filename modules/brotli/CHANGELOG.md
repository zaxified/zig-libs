# brotli — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz reach: `fuzzDecompress` decompressed the EMPTY SLICE and nothing
  else, ever. The fourteen google/brotli reference streams were `@embedFile`d into
  `fuzz_seed_corpus` and indexed with `smith.index(...)` — but the array was **never
  handed to `std.testing.fuzz` as a `.corpus`**, so outside `--fuzz` the target ran the
  one input a corpus-less target gets: the empty one, whose every draw collapses to a
  minimum. Traced 2026-09-07: `index(14)` → 0 (`empty.compressed`, 1 octet),
  `boolWeighted(1, 4)` → false, `valueRangeAtMost(u16, 0, 1)` → 0, so `keep` = 0, no
  extension, no point damage, `decompress(allocator, buf[0..0], …)`. The keep/extend/
  damage generator and its two paragraphs of measured design justification never ran in
  the ordinary lane at all; the `@panic`-probe reachability claim was made under `--fuzz`
  and says nothing about it. The generator is gone and the reference streams are now the
  corpus they were always meant to be — a fuzzer handed real streams mutates them, which
  is what the generator was approximating. ⚠ The buffer was also 1024 octets while three
  of this module's own reference streams are 10 004, 50 096 and 50 100, so the largest
  inputs it owns could not have passed through its own harness even with the corpus wired
  up; the buffer is now 51 200 and those three are in the corpus. A corpus guard pins
  19 non-empty seeds, 18 decoded, 2 refused and **981 867 output octets** (0 before).

- **2026-09-06** — **The module no longer ships foreign source, and its test suite no
  longer needs `python3`.** `src/reference_interop.zig` — which embedded a Python
  driver and spawned `python3 -c` from inside `test-brotli` — is gone. The live
  comparison against the reference implementation (google/brotli via the Python
  `brotli` C extension) is now a standalone program, `tools/interop.zig` +
  `tools/reference.py`, run by `zig build interop-brotli` and compile-checked by
  `zig build check-interop`; it is never built by `test-brotli` and never by
  `zig build`. Consumer-visible: `zig build test-brotli` runs 53 tests with **no
  skips** where it previously ran 54 with 4 skipped on any machine without the
  package (i.e. all of CI). `zig build interop-brotli -- --capture` freezes what the
  reference did into two committed fixtures: `src/testdata/ref/*.br`, 24 streams the
  reference compressed (five qualities on `alice29.txt` as before, plus three window
  sizes and q1/q11 over the rest of the corpus — decoder coverage rises from 5 cases
  to 24), and `src/testdata/interop_blessed.zig`, which pins the SHA-256 of the exact
  stream google/brotli accepted for each of the 45 input shapes the sweep covers. An
  encoder change that alters any output now fails `test-brotli` until it is re-blessed
  against a real google/brotli. New `src/interop_corpus.zig` holds the shapes and the
  stream matrix both sides share, exposed as `brotli.interop_corpus` solely so the
  out-of-tree program can reach them; it is not part of the compression API. See
  `NOTICE` for the attribution the new `src/testdata/ref/` files carry.
- **2026-08-06** — Security audit: four findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against RFC 7932 Appendix A's
  published test vectors.
- **2026-07-29** — The encoder now actually compresses. It was store-mode only (ratio
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

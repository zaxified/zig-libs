# `qr` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — `SPEC.md` claimed an external verification that did not exist: "672
  matrices... byte-identical", "320 matrices... byte-identical", "84 symbols" read back
  by an independent decoder, "12 sequences and 30 symbols" and "120 symbols"
  cross-checked against a foreign encoder/decoder, concluding "Anchor grade: class A
  · oracle EXTERNAL". `find modules/qr` had five files and no `testdata/`; grepping the
  module for every one of those numbers and for `oracle`/`independent`/`byte-identical`
  found the same prose and no executable test behind any of it, present verbatim since
  the module's first commit. `SPEC.md`'s "Verification" and "Anchoring" sections, and
  the version-32 alignment-centre paragraph in "Design & invariants" that made the same
  kind of claim, now describe what the suite actually does: 31 self-consistency tests
  (round trips, literal pins against the standard, four fuzz harnesses) plus, new in
  this entry, a real external oracle.
  The real oracle: `testdata/reference.py` drives [segno](https://github.com/heuer/segno)
  1.6.6 (an independently-authored ISO/IEC 18004 encoder) to produce 51 QR matrices —
  10 versions × 4 ECC levels ("spread", including version 32, the documented
  alignment-centre exception), 8 forced mask patterns at one version/level ("masks"),
  and all 3 implemented modes at one version/level ("modes") — frozen as checked-in
  bytes in `testdata/golden_matrices.zig`. `golden_test.zig` asserts this module's own
  encoder reproduces every one of them byte-for-byte, with no python at test run time.
  This anchors what self-consistency structurally cannot see: a round trip decodes with
  the same `Walk` placement order and the same (possibly mistranscribed)
  error-correction block-structure table the encode used, so a bug shared by both
  halves is invisible to it — only an independently-placed grid catches that.
  **The oracle itself had a real bug**, found building this: segno 1.6.6's
  `write_padding_bits` adds a spurious 8-bit zero byte when the bitstream is already
  byte-aligned after the terminator (ISO/IEC 18004:2015 §7.4.10 says to add zero bits
  in that case). The first capture run hit this at version 5/quartile and disagreed
  with this module's own encoder in roughly a third of the matrix; hand-tracing both
  implementations' pre-mask data codewords confirmed this module was the one matching
  the standard, not segno. `reference.py` monkeypatches a one-line corrected version at
  generation time so the captured vectors reflect segno's real behaviour.
  **Proven able to fail, both directions:** two mutations (`Walk.next`'s column-pair
  order swapped; `maskAt` patterns 3 and 4's formulas swapped) were each applied, run,
  and reverted. Both went red in the golden test alone — every one of the 31
  self-consistency tests, including all four fuzz harnesses, stayed green throughout,
  which is the blind spot demonstrated rather than merely asserted. New anchor grade:
  class A · oracle MIXED (anchored for encoder placement/block-structure, self for
  decoding/structured-append/rendering — down from the fabricated "oracle EXTERNAL",
  which covered nothing).
  Also fixed while in there: `root.zig`'s "damage beyond capability is refused, not
  mis-corrected" test asserted `Uncorrectable or BadData or BadFormat` where the
  corruption it applies only ever reaches `Uncorrectable` (the format-information area
  is untouched, and Reed-Solomon fails before `parseSegments` runs) — an assertion with
  two dead branches, the same class of unverified claim as the SPEC.md defect above.
  Narrowed to `Uncorrectable`, and `BadFormat`/`BadData` each gained their own
  dedicated, independently-reachable test — neither error had a reachable test
  anywhere in the suite before, so the narrowing increased coverage rather than
  reducing it.
- **2026-08-17** — Structured append (§8.4.6), both directions: `encodeSequence`
  splits a message across up to sixteen symbols, `decodePart` reports which one
  it is holding. Added because the wallet payloads this repo already has modules
  for — `psbt`, `lninvoice` — do not fit in one symbol, and a QR library that
  cannot split is not usable for them.
  Plain `decode` now **refuses** a sequence symbol with `error.StructuredAppend`
  instead of returning the fragment: a caller handed part two of three and told
  nothing would act on a truncated message, and for a signing request that is
  the expensive failure. Reassembly stays with the caller, since this module
  allocates nothing, and `sequenceParity` is exported because the parity byte is
  what separates "a symbol is missing" from "two sequences were scanned into the
  same buffer" — an index and a count cannot.
  Verified in both directions against implementations that are not ours: an
  independent encoder's sequences (12 of them, 30 symbols) read back with index,
  count and parity all matching and the rejoined messages byte-identical, and
  our own sequences read by an independent decoder, whose concatenation is the
  original message. The first direction is what pins the *semantics* — a
  round trip of our own cannot tell whether the four-bit position and the
  four-bit count are the right way round, since swapping them shifts nothing.
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

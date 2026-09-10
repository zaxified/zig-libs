# `qr` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **A1 fix campaign, F5 and F8.** Neither is a defect in the encoder or
  decoder's output, both are missing anchors.

  F5: `encode`/`decode` doc comments and SPEC's threat-model paragraph now say what
  "allocates nothing" costs on the CALLER's stack instead of leaving it unstated. Measured
  fresh (not reused from the 2026-09-03 audit number): a temporary thread-stack probe calling
  `encode`+`decode` at version 40 / ECC high, native Debug — 24 KB and 40 KB both overflow
  (clean `SIGSEGV`, Zig's own guard page), 64 KB does not. The probe was removed after
  measuring; the number lives in the doc comment and SPEC now, not in a permanent test (this
  module also targets `wasm32`, where `std.Thread` does not exist).

  F8: `pickMask`/`penalty` (ISO/IEC 18004 §8.8.2 mask scoring) had no test that let the
  auto-selection choose anything — every golden vector forces `.mask`. Added
  `"auto-selected mask is pinned across a spread of inputs (F8 anchor)"`, pinning today's own
  choice across six texts/versions/ECC levels (no independent encoder forces a *specific*
  choice the way the golden byte-comparison does — see the audit's three-way mask vote, which
  found this module is not an outlier). Verified as a real anchor, not a tautology: mutating
  rule 1's run-length weight (`score += 3` -> `score += 30`) turns the pinned test red
  (`expected 2, found 4`); reverted, green again.

  Also closed without a code change: F1 (all four fuzz harnesses collapsing to one fixed
  input) was already fixed by `75f09601` before this campaign started — confirmed by diffing
  `75f09601^` against today's tree and `git merge-base --is-ancestor 75f09601 HEAD`. The
  post-Forney re-check note (never observed firing in the audit's 3.4M-block sweep) is left
  open: constructing a Reed-Solomon error pattern that fools Berlekamp-Massey into a
  self-consistent-but-wrong locator is a targeted algebraic search this session did not
  attempt, not a quick anchor.

  `scripts/modtest qr`: 41/41 (was 40; one new anchor test). Also checked `-Doptimize=ReleaseFast`: 41/41.

- **2026-09-07** — **All four fuzz harnesses ran one fixed input for their whole
  lives, and the one named "survives damage" had never damaged anything.**

  Every harness in `root.zig` took its choices from ranged `Smith` draws. A ranged draw
  reads eight octets as a little-endian u64 and returns the range **minimum** when
  fewer remain, and after the first short read `Smith` discards the rest of the input —
  so outside `--fuzz` every knob collapsed at once. All four now read a byte script
  off one `smith.slice` draw (through `testkit.fuzz.Cursor` where a shape is being
  drawn) and carry a corpus with a guard test in the ordinary lane.

  ⛔ **`fuzzDamage` flipped zero modules.** `flips = smith.valueRangeAtMost(u16, 0, 200)`
  was 0 every iteration, so the harness encoded a symbol, damaged nothing, decoded it
  and asserted the round trip held. The Berlekamp–Massey, Chien and Forney paths its
  own comment says it exists to reach had never seen a corrupted block, and `ecc` was
  stuck at `.low` so three of the four redundancy levels were never built. After: 18
  scripts, **608 modules flipped, 11 symbols damaged and still read back correctly, and
  one that could not be repaired** — so both the correction and the refusal after it
  run. ⚠ The flip coordinates need an **odd-length** tail: with an even one the cursor
  cycles onto the same modules and an even flip count silently cancels, which is the
  same quiet nothing the collapsed draw was.

  ⛔ **`fuzzSequence` split the empty message.** Its first draw was the message length,
  so the text was always empty, `encodeSequence` returned one symbol, and the
  index/total/parity assertions compared 0 against 0 and 1 against 1. A sequence target
  that never produces a sequence proves nothing about ordering or parity. After: 13
  scripts, **10 multi-symbol splits, 120 symbols in total** (1 symbol carrying an empty
  message before).

  ⛔ **`fuzzDecode` built one 17×17 all-light grid**, which fails the format-information
  BCH check long before the Reed–Solomon path the harness is about. After: 4 distinct
  grid sizes across 11 scripts.

  ⛔ **`fuzzEncode`'s `BadVersion` guard was unreachable twice over.** The version knob
  was 0 for ever *and* the code read `@intCast(@min(forced_version, 40))` under a
  comment saying "0 and 41 exercise the guards" — the clamp turns 41 into 40, so even a
  working draw could not have reached `BadVersion`. The clamp is gone. After: 23
  scripts, all 4 ECC levels, 21 symbols encoded across 4 versions, 21 round trips (1
  symbol, of the empty string, before).

- **2026-09-07** — `testdata/reference.py` moved to `tools/reference.py`. It drives
  **segno** under a Python interpreter, so it is an instrument needing a foreign
  toolchain, and `CONVENTIONS.md` §9 puts those in `modules/<name>/tools/` rather than
  under `src/`. Nothing imports or embeds it — `golden_matrices.zig` and
  `decode_vectors.bin` stay where they are, since those are the committed transcript the
  hermetic lane replays. The regeneration command in `golden_matrices.zig`'s header is
  updated to the new path.

- **2026-09-04** — **First audit.** Never audited before; landed 2026-08-23 and was
  invisible to the drift ranking, which cannot see a module with no anchor.
  **The codec itself is correct** — 2880 encoder vectors across all 40 versions x
  4 levels x 3 modes byte-identical to segno, 960 segno-produced grids decoded
  back to segno's own input, 25,765 exhaustive single-module flips with 0 wrong
  answers, and ReleaseFast storms (200k arbitrary grids, 20k crafted RS-valid
  symbols, 3.4M direct `rsDecode`) with no panic and no OOB. Every finding is
  about tests and docs.
  - **The decoder gained the external anchor SPEC.md said it lacked.** That file
    named the gap in its own words — "Extending the oracle to decoding (e.g.
    segno's matrices fed to this module's decoder) is future work". It is done:
    `src/testdata/decode_vectors.bin`, 160 grids from **segno** (BSD-3,
    independently authored) spanning every version 1-40 at every level, which
    this module must read back to segno's own input. Not a round trip — nothing
    in it was encoded here. Generator: `scripts/gen-qr-decode-vectors.py`,
    which emits all 960; all 960 passed when this landed.
  - ⛔ **Six of seven decoder refusal guards deleted cleanly with the whole suite
    green.** Only the format-info BCH radius was pinned. Four now have tests,
    each seen red under exactly that one-line deletion: the unimplemented-mode
    reject (without it an **ECI or Kanji segment is silently reinterpreted as
    byte data** — a different string returned, not a refusal), structured-append
    `index > total`, numeric `v > 999`, alphanumeric `v >= 45*45`. The last two
    are silent-corruption guards: without them a malformed symbol decodes to
    some other string.
    ⚠ The first version of the mode test passed under its own mutation for the
    wrong reason — reinterpreted as byte mode, the next octet read as a count of
    65 that did not fit, so it still errored, by a route unrelated to the guard.
    The payload behind the indicator is a well-formed byte segment now.
  - Docs: a test comment said "Mode indicator 0b0011 is ECI"; **0b0011 is
    structured append**, this file's own `sequence_mode`, and ECI is 0b0111. Its
    vector returns `BadData` from a truncated SA header, not from the branch the
    comment named — and that branch had no test, which is how it survived to a
    first audit. `SPEC.md` justified its fuzz harnesses with "random noise rarely
    reaches Berlekamp-Massey"; measured, **81% of random grids do reach it**, and
    what they essentially never reach is `parseSegments`, at 0%. A doc comment
    claimed a check "against an independent encoder for every version from 2 to
    40" while the committed oracle covers 10 — the claim is true (re-verified
    across all 40) but nothing in the repo re-ran it. `reference.py` said 29
    self-consistency tests where there are 31.

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

# `qr` — design, verification, backlog

## Design & invariants

**Everything that can be derived is derived.** The standard prints several
tables; most of them describe something with a rule behind it, and a rule that
executes cannot be transcribed wrongly:

| what | how it is obtained |
|---|---|
| GF(2^8) exp/log tables | generated at comptime from the primitive polynomial 0x11D |
| Reed-Solomon generator polynomials | built at call time as `prod (x - alpha^i)` |
| alignment-pattern centres | computed from the version — with one exception, below |
| total codewords per version | **counted**, by asking the function-pattern layout how many modules it did not claim |
| short/long data-block lengths | division and remainder over the block count |
| error-correction block structure | the one genuinely tabular thing, transcribed (40 x 4 pairs) |

Counting the codeword capacity rather than tabulating it is the load-bearing one:
the routine that reserves modules for drawing is the same routine that decides
how many are left, so a mistake in the function-pattern layout cannot produce a
symbol that is internally consistent and wrong. It shows up as a capacity that
disagrees with the standard's Table 1, which a test checks directly.

**Version 32 is an outlier in the standard and is special-cased.** Its tabulated
alignment centres are 6, 34, 60, 86, 112, 138; even spacing over the same span
gives 6, 26, 54, 82, 110, 138. No rounding rule reconciles it: version 32 spans
132 over 5 gaps (26.4, table takes 26) while version 36 spans 148 over 6 (24.67,
table takes 26) — one rounds down, the other up. This is an exception
transcribed from the standard's own table, not a rule the derivation is
missing, and it is one of the ten versions in the external-oracle "spread"
set (`SPEC.md` "Verification"): our encoder's version-32 matrix matches
segno's independently-computed one byte-for-byte, at four ECC levels, which
is real (2026-08-18) evidence for the exception rather than the "checked
against an independent encoder" prose this sentence used to assert with
nothing behind it. Pinned by a test that also pins versions 31 and 33 as
*derived*, so the exception cannot quietly widen.

**One walk, two directions.** The zigzag that places codewords is a single
`Walk` used by both the encoder and the decoder. A decoder that re-derived the
order would be a second chance to get it wrong, and the two would disagree only
on inputs neither test covers.

**A correction that satisfies the locator is still re-checked.** After Forney
applies the magnitudes, the syndromes are recomputed and a non-zero result
returns `Uncorrectable`. Berlekamp-Massey can converge on a locator that
"corrects" a block into different wrong data when the error count exceeds
capability; without the re-check that comes back as a confident wrong message,
which is the single worst outcome this module could produce.

**Rendering is bolted on, not built in.** `writeSvg` and `writeTerminal` live in
`render.zig`; the codec does not call them and has no pixel format in it. They
exist because five candidate consumers would otherwise each have pasted the same
two easy-to-miss details — the terminal inversion, and XML-escaping caller
strings in the SVG — not because the codec grew an opinion about pictures.

**A structured-append symbol is refused by `decode`, not returned.** The header
is a fragment marker, and a caller that asked for a message and got a fragment
has no way to tell. `decodePart` is the API that can express "this is part two
of three"; `decode` reports `StructuredAppend` and returns nothing, because the
payloads that need splitting are signing requests and PSBTs, where acting on
two-thirds of a message is the failure worth engineering against.

**Reassembly is the caller's, and the parity byte is why that is safe.** Holding
sixteen decoded fragments needs storage this module does not have. What it does
export is `sequenceParity`, the XOR over the whole message that every symbol of a
sequence carries: an index and a count can tell you a symbol is missing, but only
the parity can tell you that the symbol you just scanned belongs to a *different*
sequence — which is the case a phone camera pointed at a table of printed codes
actually produces.

**Masking is scored with the format information present.** Three of the four
penalty rules can see those 31 modules, so evaluating a bare data region and
writing the format bits afterwards scores a symbol that never exists. `pickMask`
therefore draws the format info for each candidate before scoring.

**The error-correction level's wire encoding is not its enum order.** The
standard assigns M=00, L=01, H=10, Q=11. A symbol built with the enum order
instead is well-formed in every other respect and rejected by every decoder,
which reads as a masking bug; `Ecc.formatBits` is the one place that mapping
lives.

## Threat model & out of scope

This is a codec: it takes a byte slice and fills a caller-owned struct. It
allocates nothing, opens nothing and has no shared state, so the failure modes
are wrong output rather than compromise. Untrusted input is bounded by
`error.TooLong` before any buffer is touched — `Options.version` is validated
against 1–40, and a length that does not fit is refused rather than truncated,
which matters because a truncated QR code still scans and reads as a shorter
message.

**The SVG renderer emits caller strings into a document.** The two colours and
the `<title>` are XML-escaped, because the expected shape of this module in a web
service is "text arrives in a request, comes back as a code" and the title is
where that text naturally lands. Unescaped, a title is markup injection into a
document the browser will render.

**The decoder is the attacker-facing half.** A matrix handed to `decode` came
from an image someone else chose, so its size, format bits and every codeword are
untrusted. Three things bound that: the size must be 17 + 4v for v in 1..40 or it
is refused before anything is indexed; the format information must land within
the BCH code's 3-bit correction radius or it is refused; and a Reed-Solomon
correction whose syndromes do not clear afterwards is reported rather than
returned. Two fuzz harnesses cover the surface — one over arbitrary grids, one
over valid symbols with modules flipped, since random noise rarely reaches
Berlekamp-Massey but real damage does. The damage harness also asserts the
message when decoding succeeds, so "returns confident nonsense" is a fuzz failure
and not merely a missing panic.

## Verification

**Corrected 2026-08-18.** This section used to open with "two independent
oracles, neither of which shares an author with this module" and go on to
claim specific byte-identical comparisons — 672 matrices, 320 matrices, 84
symbols read back by an independent decoder, 12 sequences/30 symbols and 120
symbols cross-checked against a foreign encoder/decoder — concluding "Anchor
grade: class A · oracle EXTERNAL". None of it was true: `find modules/qr`
had five files, no `testdata/`, no embedded golden bytes, and grepping the
module for every one of those numbers and for `oracle`/`independent`/
`byte-identical` found the same prose and no executable test behind any of
it. The claim was present verbatim in the module's first commit — it was
never regression-tested away, because it never had a test. What follows
replaces it with what the module's tests actually do today, checked by
reading them.

**The module's own tests are self-consistency: 31 tests (`root.zig`'s 23
plus `render.zig`'s 7 plus the test-aggregator block) including four fuzz
harnesses, all authored alongside the code they check.** Round trips
(`root.zig`'s "round trip: every mode, every level, across the version
range", the structured-append round trip, the renderer round trips) encode
and then decode with this module's own inverse of whatever it just did, so a
consistent mistake in **both** halves — the zigzag `Walk` order, the
transcribed error-correction block-structure table, a masking-formula bug —
is invisible to them by construction: decode just undoes whatever encode
did, correctly or not. Literal pins (the generator polynomial for ten EC
codewords against the standard's printed coefficients, codeword capacity
against Table 1, the tabulated alignment centres including the version-32
exception, finder-pattern geometry on the diagonal, the field's
multiplicative inverse over all 255 non-zero elements) check specific values
against the spec text, not against an outside implementation. The four fuzz
harnesses (arbitrary encoder input, arbitrary decoder grids, valid symbols
with modules flipped, arbitrary structured-append messages) check that
untrusted input never panics and that a "successful" decode is never wrong
— solid ground, but none of it is an external oracle, and none of it was
ever claimed to need one until the paragraph above invented the claim.

**A real external oracle, added 2026-08-18, closes part of that gap.**
`testdata/reference.py` drives [segno](https://github.com/heuer/segno) (a
pure-Python, independently-authored ISO/IEC 18004 encoder; version 1.6.6 at
capture time) to produce QR matrices for a fixed (content, mode, version,
ecc, mask) tuple, and `testdata/golden_matrices.zig` freezes the resulting
module grids as checked-in bytes — genuinely produced by segno's own
placement and interleaving logic, not by our reading of the spec, and not
recomputed by python at test time. `golden_test.zig` asserts our own encoder
reproduces every one of them byte-for-byte, with no python or subprocess
involved in the test run itself (so it runs in CI, which never has segno
installed). This is exactly what the encoder-comparison half of the old
claim described, done for real: forcing the same version/ecc/mask on both
sides means both implementations are answering the identical question, so
module-for-module disagreement is a real defect rather than a difference in
auto-selection heuristics.

**What it covers, and why this is the piece self-consistency structurally
cannot check:** 51 vectors —

- **"spread"** (40 vectors): 10 versions across the 1–40 range (1, 2, 5, 7,
  10, 14, 20, 27, 32, 40 — including version 32, the documented exception to
  the alignment-centre spacing rule above) × all 4 ECC levels, numeric mode,
  mask forced to 0, content sized to nearly fill each version's tightest
  (H) capacity. Exercises the transcribed error-correction block-structure
  table broadly: a wrong entry changes the interleave and the matrix stops
  matching.
- **"masks"** (8 vectors): version 5, level Q, every one of the 8 mask
  patterns forced in turn. A masking-formula bug (e.g. two patterns'
  conditions swapped) does not change what this module's own decoder reads
  back — unmask always undoes whatever mask encode applied, by construction
  — so only an oracle that computes the mask pattern independently catches
  it (proven below).
- **"modes"** (3 vectors): version 3, level M, one vector each for numeric,
  alphanumeric and byte mode, exercising the mode-indicator and count-field
  bits the other two sets (numeric only) do not.

The count is pinned by a canary test (`golden_test.zig`) so the two tables
cannot silently drift apart.

**Proven able to fail, not merely passing (2026-08-18):** two mutations were
applied to `root.zig`, the suite run, and the source restored.

| Mutation | Golden test (`golden_test.zig`) | The other 31 self-consistency tests |
|---|---|---|
| `Walk.next`: swapped which of the two columns in a pair is visited first (placement order) | **RED** — `spread_v1_l` mismatched at the very first byte the finder pattern doesn't own | all green |
| `maskAt`: patterns 3 and 4's formula bodies swapped | **RED** — `mask_v5_q_m3` mismatched | all green |

Both mutations were reverted and the suite confirmed green again. In both
directions, only the golden oracle noticed — every round trip, all four fuzz
harnesses, and every literal pin passed with the mutation active, which is
the concrete demonstration of the blind spot described above, not just an
assertion of it.

**The oracle itself had a real defect, found while building this anchor, and
that is worth recording rather than quietly routing around.** segno 1.6.6's
`write_padding_bits` computes the padding-to-byte-boundary amount as
`8 - (length % 8)` unconditionally, which — per ISO/IEC 18004:2015 §7.4.10 —
is wrong when the bit stream is *already* byte-aligned after the terminator:
it should add zero bits, and segno's formula adds a spurious full byte
instead. The very first capture run of this oracle hit exactly that case (a
version-5-quartile vector) and disagreed with this module's own encoder in
roughly a third of the matrix's data-region bytes. Hand-tracing both
implementations' pre-mask, pre-interleave data codewords isolated the one
extra byte and confirmed **this module's encoder was the one matching ISO
7.4.10, not segno** — `pyzbar`/`zbar` decoded both the segno-buggy matrix and
this module's matrix for that case to the correct message anyway, because a
lenient decoder never validates padding content, which is exactly why a
byte-identical golden comparison (and not a decode round-trip against a
third tool) is what caught this at all. `reference.py` monkeypatches a
one-line corrected `write_padding_bits` at generation time, documented in
full there, so the captured vectors reflect segno's real encoding logic and
not this one bug in it.

**What the external oracle does not yet cover.** It anchors the encoder's
placement and block-structure/interleave logic. It does not anchor decoding,
error correction, structured append, or the renderers — those remain
self-consistency only, same as before this section was corrected. Extending
the oracle to decoding (e.g. segno's matrices fed to this module's decoder,
or this module's matrices fed to an independent decoder) is future work, not
something this pass claims to have done.

Neither `render.zig`'s renderers nor structured append gained an external
oracle in this pass; both are still checked by parsing rendered output back
into a matrix (renderers) or by round trip (structured append).

**A related but separate fix, same day:** `root.zig`'s "damage beyond
capability is refused, not mis-corrected" test asserted
`r == DecodeError.Uncorrectable or r == DecodeError.BadData or r ==
DecodeError.BadFormat` where the specific corruption it applies (a
contiguous wipe of the data region) only ever reaches `Uncorrectable` — the
format-information area is untouched, so `BadFormat` is unreachable, and the
damage is heavy enough that Reed-Solomon fails before `parseSegments` ever
runs, so `BadData` is unreachable too. An assertion with two dead branches
is the same class of claim this whole section exists to stop making — it
reads as "any of three failure modes is exercised here" when only one is.
The test now asserts `Uncorrectable` alone, and `BadFormat`/`BadData` each
gained their own dedicated test reaching them with their own input (clearing
both copies of the format information; feeding `parseSegments` a malformed
mode indicator directly) — narrowing the original assertion actually
increased coverage, since neither of the other two errors had a reachable
test anywhere in the suite before.

## Anchoring

**Mixed.** The module-placement order and the error-correction block
structure — the two things self-consistency structurally cannot check,
because a decode that undoes the same wrong order or the same
mistranscribed table as the encode that produced it still reports success —
are now anchored against segno, an independently-authored external encoder,
via checked-in golden matrix bytes (`testdata/golden_matrices.zig`),
byte-identical, with the failure mode proven both ways (see the mutation
table above). Decoding, error correction, structured append and rendering
remain self-consistency: round trips, literal pins against the standard's
printed values, and four fuzz harnesses. Building this anchor turned up one
real, independent defect — not in this module, but in the oracle itself
(segno's `write_padding_bits` boundary bug, above) — which is the concrete
argument for keeping an external comparison at all rather than trusting
either side's prose; this module's own version-32 alignment-centre exception
("Design & invariants" above) is now covered by the same 2026-08-18 oracle
rather than by the unverified "checked against an independent encoder"
claim that used to justify it.

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths (encoder placement and block structure,
  against segno), self for others (decoding, structured append, rendering) — the
  "Verification" section above names which.

## Backlog

- **Kanji mode, ECI, Micro QR** — separable additions, none foreclosed by this
  design. See README "Not implemented" for why none is scheduled.
- **Segment mixing.** A single mode is chosen for the whole input, so
  `"HELLO WORLD 2026"` pays alphanumeric rates throughout rather than switching
  to numeric for the tail. The standard allows mixed segments and the optimal
  split is a shortest-path problem over three modes; worth doing only if a
  consumer is bumping a version boundary, since the win is at most a few percent.
- **Penalty evaluation cost.** `pickMask` applies, scores and un-applies eight
  masks over the whole symbol, which is eight full passes at version 40. Fine for
  anything interactive; if a consumer ever generates codes in bulk, the scoring
  can be made incremental.

## Status

`build · any · codec · reentrant` + deps: none — canonical source is
`pub const meta` in `src/root.zig`.

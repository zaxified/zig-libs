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
table takes 26) — one rounds down, the other up. Every version from 2 to 40 was
checked against an independent encoder and 32 is the only disagreement, so this
is an exception in the table and not a rule the derivation is missing. Pinned by
a test that also pins versions 31 and 33 as *derived*, so the exception cannot
quietly widen.

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

**Two independent oracles, neither of which shares an author with this module.**

1. **An independent encoder**, compared matrix-for-matrix with the mask forced so
   that both implementations are answering the same question. 672 matrices over
   7 inputs x 4 levels x 3 versions x 8 masks, byte-identical; plus a sweep of
   **all 40 versions x 4 levels x 2 fill levels = 320 matrices**, byte-identical.
   The sweep is what exercises the transcribed block-structure table: a wrong
   entry changes the interleave and the matrix stops matching.
2. **An independent decoder**, handed this module's output and asked what it
   reads. 84 symbols, every one read back as the exact input. This catches a
   class the encoder comparison cannot: two encoders agreeing on a matrix that
   no reader accepts.

**Decoding is verified in both directions too.** Round trips cover every mode,
level and a spread of versions; correction is tested at exactly the capability
boundary — eight corrupted codewords in a version 1-H block succeed, nine are
refused — by damaging one module per codeword so the count is exact rather than
estimated. And the foreign encoder's matrices are fed to **our** decoder: 120
symbols over 6 inputs x 4 levels x 5 versions, all read back exactly.

The oracle comparison found one real defect — the version 32 alignment centres
above — after the module's own tests were green, which is the reason to have it.

Neither oracle's source was read, and no third-party QR implementation
contributed to the design; the relationship is testing, not provenance
(`CONVENTIONS.md` §5: a black-box oracle needs no NOTICE entry, an implementation
studied as a design reference does).

**The module's own tests** pin values rather than mechanisms: the generator
polynomial for ten EC codewords against the coefficients the standard prints,
codeword capacity against Table 1, alignment centres against the tabulated ones,
and finder-pattern geometry on the diagonal so a single wrong ring cannot average
out. The field is checked by exhaustive multiplicative inverse over all 255
non-zero elements.

## Anchoring

**External.** Expected values come from outside this repo in both directions: an
independent encoder's matrices, compared byte-for-byte, and an independent
decoder's reading of ours. Neither is ours and neither was read; both can fail
us, and one already did — the version 32 alignment centres. The transcribed
values (the standard's block-structure table, the Table 1 capacities, the printed
generator polynomial for ten EC codewords) are self-anchored *as transcriptions*
but every one of them is downstream of a matrix the external encoder either
matches or does not.

**Anchor grade:** class A · oracle EXTERNAL

## Backlog

- **Kanji mode, ECI, structured append, Micro QR** — separable additions, none
  foreclosed by this design. See README "Not implemented" for why none is
  scheduled.
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

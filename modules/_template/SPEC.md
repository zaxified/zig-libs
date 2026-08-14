# `<name>` — specification

<!-- SKELETON. 219 of 225 modules have a SPEC.md; the six that do not are the
     smallest glue. Delete a heading that genuinely does not apply to this
     module rather than leaving it empty — an empty heading reads as an
     unanswered question, and this file is where a reader goes to find out
     what was decided and what was refused. -->

## What this module is, and what it is not

One paragraph. Then the scope line that matters most: **what a reader might
reasonably expect here and will not find.** Name it, and say whether that is
deferred or refused. A capability silently absent is the thing that wastes
someone's afternoon.

## Wire format / algorithm

The construction, in enough detail that a second implementation could agree
with this one byte for byte. Cite the RFC, paper or published vectors by
section number, not by name alone.

## Constant-time contract

⚠ Only if this module touches secrets. State **which values are secret**, which
operations are claimed constant-time w.r.t. them, and — the part usually
missing — **what is deliberately not**. A blanket claim is worse than none: it
is what a reader relies on when they should be careful.

If a claim is machine-checked, say by what (`scripts/ctgrind.sh <name>`, a row
in `scripts/ctgrind-expected.tsv`). If it rests on reading the code, say that
instead. Those are different grades of evidence and must not be written alike.

## Limits and refusals

Every hard bound the code enforces, with the number and where it comes from.
A limit derived from a spec cites the spec; a limit chosen by us says so and
says why. If a constant is pinned by a test, name the test.

## Anchoring

Where the expected values in the tests come from. Distinguish, in these words:

- **External anchor** — published vectors, bytes captured from a foreign
  implementation, or a live run against a foreign peer. It can fail us.
- **Re-derived** — an in-house oracle reaching the answer another way. Catches
  a typo; does **not** catch a shared misreading of the spec.
- **Self** — we wrote the expected values from our own reading.

⚠ Never record a design reference ("we looked at how X does it") as an anchor.
State the grade in the machine-checked form `check-catalog` reads:

**Anchor grade:** class <A|B|C|D> · oracle <EXTERNAL|REDERIVED|MIXED|SELF|n/a>

Class A/B means an outside truth exists (a wire format others must agree with, or
a published construction with vectors) and the oracle may not be `n/a`. Class C/D
means none exists — an internal algorithm, or our own design — and the oracle must
be `n/a`, because grading one invents anchor debt that cannot be paid.

## What is deliberately not done

Decisions to refuse work, with the reason. This is the section that stops the
same proposal arriving every few months — and the one whose absence made a
separate archive necessary until 2026-08-13. Distinguish **not now** from
**never** from **superseded by something external**; they are not the same and
get confused constantly.

## Open

What is known to be missing or unverified. An honest gap here is worth more
than a claim that does not hold.

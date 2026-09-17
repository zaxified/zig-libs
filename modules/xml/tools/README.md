# `xml` verification instruments

Six instruments, run by hand. None is wired into `zig build`: two need a
**foreign toolchain** (`xmllint`/libxml2 and Python's expat), the corpus
generators write ~12 MB, and the mutation runner costs a full build plus 69
tests per row. `zig build test-xml` must require none of it
(`CONVENTIONS.md` §9).

Figures below were measured on 2026-09-17 against the tree as it stands.

## Three implementations over one corpus

| tool | question it answers |
|---|---|
| `gen_hostile.py` | The 60 hostile/differential documents, as code rather than as files in a droppable cache. |
| `gen_amp.py` | The 21 amplification/complexity documents behind the memory and throughput numbers. |
| `differ.sh` | Runs this module, libxml2 and expat over the same documents and compares verdicts. |
| `probe.zig` | Verdicts, peak-live-bytes, namespace-axis cost, throughput, scan linearity, content bytes. |
| `probe_c14n.zig` | Canonicalizes through `xmldsig`'s C14N so the bytes can be held against `xmllint --c14n`. |
| `mutate.py` | Would the suite notice if a guard were removed? |

```bash
modules/xml/tools/gen_hostile.py            # -> .zig-cache/xml-corpus/hostile
modules/xml/tools/gen_amp.py                # -> .zig-cache/xml-corpus/amp
zig build-exe -O ReleaseFast --dep xml -Mmain=modules/xml/tools/probe.zig \
    -Mxml=modules/xml/src/root.zig --cache-dir <scratch>/zc -femit-bin=<scratch>/probe
PROBE=<scratch>/probe modules/xml/tools/differ.sh
```

**Measured over the 60 hostile documents: no case where this module accepts and
BOTH references reject.** That is audit F4's direction — the dangerous one for a
signature verifier — and all four of its documents now refuse:
`nam01_middledot_start` and `nam02_combining_start` give `InvalidName`,
`nam03_multiply_sign` and `nam06_attr_multiply` give `UnexpectedChar`, against
`ERR` from xmllint and `ParseError` from expat.

⚠ `nam05_colon_name.xml` (`<a:b:c/>`) is the one row where the two REFERENCES
disagree: libxml2 accepts, expat rejects, and this module sides with expat.
That is not a finding against the module, and the audit recorded it the same
way — but it is why the differential prints three columns and not two.

The remaining divergences all run the safe way (module refuses, references
accept) and are deliberate: `DuplicateId` on the signature-wrapping shapes,
`UndefinedEntity` for user-declared entities under `doctype=.ignore`,
`NamespaceError` on `xmlns:p=""`.

### The canonical form matches libxml2 byte for byte

Audit F3 was found by canonicalizing a document with a CR inside a comment and
holding the bytes against `xmllint`: `0d 0a` here, `0a` there — different
digest, a signature valid on one stack and not the other. Re-measured across
all five CR shapes (CDATA, text, comment, PI, attribute): **5/5 byte-identical**
to `xmllint --c14n`.

⚠ **Use `--c14n`, not `--c14n-with-comments`.** This libxml2 (21502) has no such
flag and prints NOTHING for it, exit 0 — a comparison that looks clean because
the oracle returned an empty string. `--c14n` already includes comments here.

## Would the suite notice if a guard were removed?

    modules/xml/tools/mutate.py               # the whole table
    modules/xml/tools/mutate.py --only M21    # rows whose id contains "M21"
    modules/xml/tools/mutate.py --controls    # only the controls

33 mutations and 2 controls. Measured: **35 rows, 26 RED, 7 GREEN, 2 BROKEN
(0 unpinned), 0 anchor problems**, every verdict pinned and re-run for
self-consistency (35/35).

### ⚠ The scratch copy is the WHOLE `src/` tree, and that is not optional

`root.zig` pulls in `xmlconf_test.zig`, which pulls in `xmlconf_vectors.zig`,
which `@embedFile`s 130 fixtures from `src/testdata/xmlconf/`. Copying the three
`.zig` files alone builds nothing — measured, it dies with
`unable to open 'testdata/xmlconf/sun-valid/valid/dtd00.xml': FileNotFound`.
`@embedFile` binds the copy to **data**, not just to source. The three
single-file modules migrated before this one never had to care, and the audit's
own `mut/` directory has an empty `testdata/`, which is part of why its snapshot
(2139 lines, 52 tests) could never have run against today's module (2724 lines,
69 tests).

### Two rows are pinned BROKEN on purpose

`M14` and `M25` are the audit's own compile-broken forms: neutralising the guard
left a local constant and a function parameter unused, which Zig refuses to
compile, so **nothing ran**. They are kept as the honest record of what was
tried, pinned `BROKEN`, with `M14b`/`M25b` — which spend the value instead —
doing the measuring and coming back RED. The runner only treats an *unpinned*
BROKEN as its own defect; a pinned one that started compiling would trip the
mismatch check instead.

This is the same trap the rest of this campaign met on `s7comm`'s `D2`, found
here first and cured the same way.

### Of seven GREEN, one is the negative control and one is a real gap

| row | what it is |
|---|---|
| `NC-no-edit` | the negative control — must be green |
| **`M10`** | **a real unpinned guard**: CR/LF normalisation in **text** |
| `M13` | equivalent mutant — the test says so itself |
| `M20` | equivalent mutant — `isXmlChar` still holds the bound |
| `M30` | equivalent mutant — `DuplicateAttribute` fires at parse time |
| `M16` | a recorded, deliberate gap |
| `M21` | a recorded, deliberate gap |

**`M10` is the one worth acting on.** Audit F3 extended line-ending
normalisation to comments and PIs and added a test — but that test
(`not-wf: line-ending normalization (XML 2.11) applies inside comments and PIs
too`) asserts only on `content.comment` and `content.pi.data`. Its own comment
says text and attribute values "already did this", and the original text path is
still held by nothing: deleting normalisation in `parseText` leaves 69/69 green.
The fix pinned the paths it added and left the path it inherited.

`M13`, `M20` and `M30` cannot fail for reasons the code states: `utf8Encode`
independently rejects a surrogate half, `isXmlChar` still bounds the char-ref
range, and a second matching attribute is `DuplicateAttribute` before `attr()`
ever runs. ⚠ The audit's F9 lists `M13` among "9 real holes"; the test written
afterwards (`not-wf: char ref onto a lone UTF-16 surrogate is rejected`)
explains why it is an equivalent mutant **today**, and keeps the assertion
anyway so it stops being redundant the moment either check changes. The test is
right and the record is stale on that point.

`M16` and `M21` are recorded decisions: F9-M16 was closed as an architectural
fix with no separately demonstrable path, and F8 was closed by documentation
alone — `findByAttr` now says openly that it does not report a second match, and
its test has only one matching element, so first-vs-last is not distinguishable
there by construction.

### One anchor rotted, and because the finding was fixed

33 of the audit's 34 anchors still match their site exactly once. `M21` named
the whole recursive `findByAttrRec`; F5-zbytek replaced that machine recursion
with an explicit heap stack **and changed the public signature** (`findByAttr`
now takes an allocator and returns an error union), so the old text matches
zero times. Re-derived against the new body.

And the command line rots separately: a bare `zig test root.zig` fails at
`root.zig:2594` with `no module named 'testkit'`. A green anchor count is not a
green runner.

## Cost, memory and complexity

**Audit F1 (`inScopeNamespaces` was O(k²)) is fixed, and the fix is visible.**
One axis call at the apex — the shape `xmldsig`'s inclusive C14N performs:

| declarations in scope | audit | today |
|---|---|---|
| 1 024 | 0.805 ms | **0.176 ms** |
| 2 048 | 3.58 ms | **0.366 ms** |
| 4 096 | 10.6 ms | **0.590 ms** |
| 8 192 | 49.5 ms | **1.170 ms** |

Quadratic (4.0–4.7× per doubling) became linear (1.6–2.1×), and 4 096
declarations went from 10.6 ms to 0.59 ms — **18× faster**.

⚠ `probe nsaxis_all` walks the axis once per ELEMENT and is DIAGNOSTIC ONLY.
`c14n.zig:304-313` calls `inScopeNamespaces` only when `is_apex`; descendants
emit just their own declarations. So the per-element sweep is a shape no
consumer performs, and its cost (32 004 000 declarations and 4.6 s at depth
8 000) must not be quoted as exposure. It is kept because it isolates per-call
cost from aggregate cost — at ~100–144 ns per declaration returned, it is the
second witness that the per-call fix holds.

**Audit F2's memory table reproduces to the byte.** `probe ratio` against
`page_allocator` — the allocator the module's own documented table was produced
with, and the one that matters, since `DebugAllocator` gives ~1.5× the peak for
the same input:

| input | peak live | `root.zig` says |
|---|---|---|
| 65 543 B | 6 339 414 B | 6,339,414 B |
| 262 151 B | 32 177 512 B | 32,177,512 B |
| 1 048 583 B | 163 139 946 B | 163,139,946 B |
| 4 194 311 B | 367 223 862 B, `TooManyElements` | 367,223,862 B (~350 MiB) |

F2 was closed by correcting the documentation rather than the behaviour, and
this is what confirms the corrected text. Note the last row: the document is
one element past `max_elements`, so it is **refused** — but the 350 MiB peak is
reached before the refusal. The cap bounds the accepted result, not the high-
water mark.

The billion-laughs shape goes the other way: 100 037 B of source with a
100 000-character declared entity produces **944 bytes live, ratio 0.01**.

**Throughput**, ReleaseFast, best of 30, on an idle machine:

| document | today | audit |
|---|---|---|
| SAML-shaped 67 446 B | 108.7 MB/s | 124.6 MB/s |
| SAML-shaped 676 046 B | 94.5 MB/s | 114.4 MB/s |
| text-heavy 1 MiB | 300.2 MB/s | 367.3 MB/s |

⚠ These are **not** a regression claim. The first time this was measured here,
a 35-row mutation table was building in the background and the same documents
read 74.4 / 80.4 / 267.0 — the load accounted for most of the gap. The audit's
own figures were taken with three concurrent agents running and it said so.
Absolute MB/s on a shared machine is a number about the machine; the ratios
(linear vs quadratic) are what survive it.

`decodeReference`'s whole-source `;` search remains linear: 10 000 → 206 µs,
20 000 → 359 µs, 40 000 → 824 µs, 80 000 → 1 502 µs. And a 200 000-deep document
is walked by the public reading APIs without touching the machine stack
(audit F5).

## What was deliberately not brought over

`.zig-cache/audit-xml` was 240 MB.

- The audit's module snapshot (`mut/root.orig.zig`, 2139 lines, 52 tests) and
  its mutant trees — a copy 585 lines and 17 tests behind the live module.
- `probe`'s `vectors` and `dump` commands, which read `xmlconf_vectors.zig`
  directly. That file is already reachable from `root.zig`, and Zig refuses a
  file belonging to two modules (`file exists in modules 'xmlvectors' and
  'xml'`). The only way back would be to add public API to the module so a TOOL
  can see its fixtures — a verification instrument must not reshape the thing it
  verifies. `xmlconf_test.zig` already drives all 130 vectors in-tree, both
  directions, with a canary pinning the counts.
- `fuzz-instrument.patch.txt` — spent: audit F6's harness reached exactly one
  empty input, and that was fixed before the fix campaign ran.

⚠ **Four documents in the audit's `amp/` had no generator at all** and would
have died with the cache. They are reproduced here from the artefacts, measured
rather than guessed — and renamed to what they actually are. The audit called
them `attrs_16k` / `attrs_64k` / `attrs_256k`, as if labelled by byte size:
`attrs_16k` is 22 294 B with 2 340 attributes, `attrs_64k` is 38 894 B with
4 000, and **`attrs_256k` was byte-identical to `attrs_64k`** (verified with
`cmp`) — one document under two names, the second promising a size it never
had. Any figure quoted against "attrs_256k" was measured on the 64k document.

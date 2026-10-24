# `xml` verification instruments

Instruments run by hand. None is wired into `zig build`: several need a
**foreign toolchain** (`xmllint`/libxml2 and Python's expat). `zig build test-xml` must require none of it
(`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.

Figures below were measured on 2026-09-17 against the tree as it stands.

## Three implementations over one corpus

| tool | question it answers |
|---|---|
| `gen_hostile.py` | The 60 hostile/differential documents, as code rather than as files in a droppable cache. |
| `differ.sh` | Runs this module, libxml2 and expat over the same documents and compares verdicts. |
| `probe.zig` | Verdicts, peak-live-bytes, namespace-axis cost, throughput, scan linearity, content bytes. |
| `probe_c14n.zig` | Canonicalizes through `xmldsig`'s C14N so the bytes can be held against `xmllint --c14n`. |

```bash
modules/xml/tools/gen_hostile.py            # -> .zig-cache/xml-corpus/hostile
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

## 2026-10-04: core vectors and the writer oracle

- `gen_core_vectors.py` — recipe for `../src/core_vectors.zig`: libxml2's (lxml's) reading of
  encoding and internal-entity cases, as the dump format the recipe defines.
- `writer_oracle.zig` + `writer_oracle.py` — differential oracle for the writer: libxml2 reads
  each original and the document `writeDocument` produced from it; their C14N must be equal.
  Measured 2026-10-04: same=119 differ=0 (28 inputs refused by one side, skipped).

## 2026-10-24: own well-formedness vectors, and the W3C suite fetched on demand

The W3C XML Conformance Test Suite is no longer vendored (its files carry no
redistribution licence; see `../NOTICE`). Two instruments replace it:

- `gen_wf_vectors.py` — recipe for `../src/wf_vectors.zig`: 491 inputs of our own
  (245 not well-formed, 246 well-formed; DOCTYPE-free, or with a no-op internal
  subset for `doctype = .ignore`, or with general entities for
  `.internal_entities`), each with libxml2's verdict and infoset DUMP from lxml
  as a black box. A deliberate deviation of this module is recorded in the
  recipe (`OURS`), never flipped silently. `--files DIR` writes the inputs as
  files (`DIR/index.tsv` lists id, mode, libxml2 verdict, recorded deviation) for
  `probe file <path> [ignore|entities]` or `writer_oracle.py`, which now reads
  its accepted documents from this recipe instead of the removed xmlconf slice.
- `xmlconf_fetch.sh` + `xmlconf_run.zig` — the real suite, never committed.
  The script downloads `xmlts20080827.zip` (pinned sha256) into the gitignored
  `xmlconf-suite/`; the runner (a Zig program, with a small hand-written scanner
  for the manifests, since they are fragments rather than documents) runs the
  not-wf (DOCTYPE-free) and valid cases and prints one summary line.

```bash
modules/xml/tools/xmlconf_fetch.sh
zig build-exe -O ReleaseSafe --dep xml -Mmain=modules/xml/tools/xmlconf_run.zig \
    -Mxml=modules/xml/src/root.zig --cache-dir <scratch>/zc -femit-bin=<scratch>/xmlconf_run
<scratch>/xmlconf_run            # from the repo root; exit 1 on an unexpected verdict
```

Measured 2026-10-24: `tests=2164 pass=883 known=1 FAIL=0`; out of scope 67 valid
cases that declare entities under `.ignore`; skipped 126 by TYPE (invalid/error),
309 for earlier editions, 770 not-wf cases that carry a DOCTYPE, 7 namespace-
ignorant, 1 for XML 1.1. The one known disagreement is `x-rmt-008b` (version `1.7`).

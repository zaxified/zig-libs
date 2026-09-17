# `xml` verification instruments

Four instruments, run by hand. None is wired into `zig build`: two need a
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

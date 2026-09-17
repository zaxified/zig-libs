# `protobuf` verification instruments

Two things live here, and they answer different questions.

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.

**`interop.zig` + `reference.py`** (already present) freeze the reference
implementation's output into `../src/testdata/` so the module's own tests can
replay it without a Python. That is the ANCHOR, taken once.

**Everything else is the differential rig**: it runs this module and Google's
own implementation side by side over the same bytes and compares them
answer-for-answer, live. An anchor catches a regression against what was true
once; the rig catches a disagreement on inputs nobody thought to freeze —
including inputs no correct encoder would ever produce.

None of it is wired into `zig build`. It needs a foreign toolchain (`pip install
protobuf`), which is why it is here and not in `src/` (`CONVENTIONS.md` §9).

## The rig, and how to run it

    zig build-exe --dep protobuf -Mroot=probe.zig \
        -Mprotobuf=../src/root.zig -O ReleaseSafe    # produces ./probe
    python3 camp2.py                                  # the hostile corpus
    python3 camp1.py 5000                             # well-formed round trips
    python3 camp5.py 50000 200000                     # the big anchor run

`gen.py` expects the built `probe` beside it. Both sides speak one line
protocol — `d <schema> <hex>` to decode, `r <schema> <hex>` to decode and
re-encode; each answers `OK <dump>` or `ERR <reason>` — so a comparison is a
string comparison and nothing is interpreted twice.

⚠ The two sides must declare the SAME schemas. `probe.zig`'s `Wide` and
`oracle.py`'s `SCHEMAS["Wide"]` are field-for-field identical (numbers 1–17,
same kinds), and so are the other four. If you add a field to one, the rig
silently stops comparing what you think it compares.

| tool | question it answers | why this tool and not a test |
|---|---|---|
| `probe.zig` | What does THIS module do with these bytes? | The module side of the line protocol. A program, not a test, so the same binary can be fed a corpus of any size. |
| `oracle.py` | What does Google's implementation do with them? | Builds descriptors at run time (`descriptor_pb2` + `descriptor_pool`), so no `.proto` and no `protoc` — only `pip install protobuf`. |
| `gen.py` | — | Generates random well-formed messages and drives both sides, pairing their answers. |
| `classify.py` | Is this an agreement, a value difference, or a policy difference? | Three outcomes that must be counted apart; see the file. |
| `camp1.py` | Do we agree on well-formed messages, decoding and re-encoding? | The baseline: if this diverges, nothing else is worth running. |
| `camp2.py` | Do we agree on ~120 hand-built pathologies? | Non-minimal varints, field 0, wire types 3–7, 4 GiB length claims, packed/unpacked confusion, overlong UTF-8, 200-deep nesting. Hand-written because a random generator does not produce these. |
| `camp4.py` | Do we agree on randomly corrupted messages? | Decision parity under mutation — the shape a hostile input actually has. |
| `camp5.py` | — | The long run: well-formed plus mutated, every divergence bucketed by CAUSE, including the ones known to be artifacts of the oracle. |

## ⚠ Known, and deliberate

- **The campaigns differ in whether a divergence is a failure, and deliberately
  so.** `camp1.py` exits non-zero on any divergence: its inputs are the
  reference's own output, so there is no artifact class and no room for a
  judgement call. `camp5.py` does not, because its own classifier knows
  divergences that are artifacts of the oracle (NaN payload normalisation,
  fields the reference reports as unknown because the tag was non-minimal), and
  failing on those would cry wolf every run. Read its buckets instead. `camp2.py`
  and `camp4.py` sit between the two — see their headers.

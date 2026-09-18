# `yaml` verification instruments

Two instruments, run by hand. Neither is wired into `zig build`: both need a
**foreign toolchain** (Python + PyYAML, one of them with libyaml's C bindings).
`zig build test-yaml` must require none of it (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners, per-finding probes and benchmarks
(`bomb.zig`, `bomb2.zig`, `perf.zig`, `pathologies.py`, `utf8_sweep.py`, `track.zig`'s
peak-memory/CPU-timing helpers, …) were **not** adopted — they anchor on source text or
measure a fixed regression, not the module's public behaviour, and rot for it
(`CONVENTIONS.md` §9's "why disposable, measured").

Figures below were measured on 2026-09-17 against the tree as it stands.

## Does an independent 1.2/1.1 implementation agree, corpus and volume?

| tool | question it answers |
|---|---|
| `ydump.zig` | The driver: reads hex-framed records from stdin, composes each through this module's PUBLIC `composeAll`, prints a canonical typed rendering (or `ERR:<name>`) — a private wire format neither side's own printer produces, so agreement isn't circular. |
| `compare.py` | 402 yaml-test-suite documents through `ydump` and PyYAML 6.0.3, with a leaf-level divergence classifier. |
| `volume.py` | 200 000 documents (yaml-test-suite seeds, 1-3 random byte edits) through `ydump` and libyaml (PyYAML's `CSafeLoader` binding) — a value differential at scale, not a throughput benchmark (no timing is recorded). |

```bash
scripts/lib/capped zig build-exe --cache-dir <scratch>/zc -OReleaseFast \
  -femit-bin=<scratch>/ydump \
  --dep yaml -Mmain=modules/yaml/tools/ydump.zig \
  -Myaml=modules/yaml/src/root.zig

modules/yaml/tools/compare.py <scratch>/ydump ~/.cache/zig-libs-yaml/yaml-test-suite-data
modules/yaml/tools/volume.py  <scratch>/ydump ~/.cache/zig-libs-yaml/yaml-test-suite-data 200000
```

The suite directory is the same external anchor `SPEC.md` §5 already names (`git clone
-b data --depth 1 https://github.com/yaml/yaml-test-suite ~/.cache/zig-libs-yaml/yaml-test-suite-data`),
not vendored into this repo.

**Measured 2026-09-17, `compare.py` (402 yaml-test-suite documents):**
`agree=213 (52.99%) diverge=189` — the low raw agreement is not a module signal:
PyYAML is YAML 1.1 and the suite is deliberately edge cases. Buckets:
`both_reject=84`, `pyyaml_rejects_zig_accepts=54` (PyYAML 1.1 stricter elsewhere),
`pyyaml_ctor_limit=26` (PyYAML can't construct an unhashable/untagged key — not a
parse disagreement), `zig_rejects_pyyaml_accepts=12` (1.2 stricter; the suite sides
with the module), the rest (`leaf_str_vs_str`, `pyyaml_dup`, `binary_tag_1.1`,
`timestamp_1.1`, `int_shape_1.1_wider`, `sexagesimal_1.1`, `null_spelling_1.1`, 1-4
each) are documented 1.1-vs-1.2 core-schema differences (`SPEC.md` §6/§8). No bucket
here is new evidence of a module defect.

**Measured 2026-09-17, `volume.py` (200 000 mutated documents vs libyaml), after
audit F11 (the scanner now rejects invalid UTF-8 and non-`c-printable` characters):**
`AGREE=174979 (87.49%)`, `zig_accepts_libyaml_rejects=21407` (libyaml is 1.1 and
stricter in places not audited item-by-item — same caveat the original audit
recorded), `libyaml_accepts_zig_rejects=3336`, `zig_accepts__libyaml_dupkey=277`,
`zig_accepts__libyaml_charset_reject=1` — and that one is a misfiled unknown-tag
error (`volume.py` buckets on the word "invalid"), not a character. Before F11 the
same run gave `AGREE=166905 (83.45%)` with `8047` in the charset bucket; the
2026-09-05 audit run gave `166958` / `7994` (the difference to 166905 was not
bisected; the mutation stream is deterministic, so it came from module or suite
changes in between).

**Licences, verified at the installed package's own metadata:**
PyYAML 6.0.3 is MIT (`pip show pyyaml` → `License: MIT`); libyaml is Expat
(`/usr/share/doc/libyaml-0-2/copyright`, Debian's copy of the upstream licence) —
both permissive, no copyleft obligation.

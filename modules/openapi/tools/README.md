# `openapi` verification instruments

One oracle, run by hand; its answers are frozen in `src/spec_oracle_vectors.zig`
and replayed by `src/spec_oracle_test.zig` in the module's own lane, with no
Python (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-openapi`: has `spec_oracle.py gen` draw route tables, registers each on a `router.Router`, builds its document with `Generator.build`, has `spec_oracle.py judge` give the verdicts, and writes (or with `--check` compares) the vectors. |
| `spec_oracle.py` | `gen`: seeded route tables (+ crafted ones). `judge`: openapi-spec-validator on every built document, and on mutations of the accepted ones; the classes where `validateOpenApi31` may answer otherwise; FastAPI's mapping of the same routes. |
| `fastapi_oracle/fastapi_paths.py` | FastAPI, in its own virtualenv outside the repository: registers each table's routes (`:name` → `{name}`, `*name` → `{name:path}`) and reduces its document to path templates → methods → path parameters. |

```bash
zig build interop-openapi              # re-take, write src/spec_oracle_vectors.zig
zig build interop-openapi -- --check   # re-take, compare with the committed file
```

Needs python3 with `openapi-spec-validator`, and FastAPI in a virtualenv OUTSIDE the repository
(a site-packages tree under `modules/` is walked by the repo's gates — `check-copyleft` reads every
licence text there), created once — the only step that needs the network:

```bash
python3 -m venv ~/.local/share/zig-libs/oracle-venvs/fastapi
~/.local/share/zig-libs/oracle-venvs/fastapi/bin/python -m pip install fastapi   # 0.142.2 when frozen
```

`ZIGLIBS_FASTAPI_PY` overrides the interpreter's path.

**What the replay holds** (re-taken 2026-10-07, openapi-spec-validator 0.7.1): 102 tables
(router patterns with `:params`, `{name}` and `{name:regexp}` captures whole and inside a
segment, and a final
`*wildcard`), every built document accepted by the validator and rebuilt byte for byte; 168
mutations (12 per kind) on which `validateOpenApi31` answers as the validator did, except the
classes SCOPE (an unknown member it does not police: it accepts), VALIDATOR_LAX (a
path parameter missing from its template, forbidden by OAS 3.1 §4.8.12.1 but let
through by the validator: it refuses) and OPENAPI_30 (it accepts 3.1.x only). And every
built document maps its routes as FastAPI 0.142.2 does: the same path templates, methods
and path parameters (102 tables, 290 templates, 70 with a capture inside a segment, 29 tables
with a regexp constraint — dropped from the template, as FastAPI is given it).
Until 2026-10-07 one crafted table held a literal `{x}` static segment, refused with
`UnresolvedPathParameter`; `router` now reads `{x}` as a capture and refuses a stray brace.

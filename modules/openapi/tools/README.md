# `openapi` verification instruments

One oracle, run by hand; its answers are frozen in `src/spec_oracle_vectors.zig`
and replayed by `src/spec_oracle_test.zig` in the module's own lane, with no
Python (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-openapi`: has `spec_oracle.py gen` draw route tables, registers each on a `router.Router`, builds its document with `Generator.build`, has `spec_oracle.py judge` give the verdicts, and writes (or with `--check` compares) the vectors. |
| `spec_oracle.py` | `gen`: seeded route tables (+ crafted ones). `judge`: openapi-spec-validator on every built document, and on mutations of the accepted ones; the classes where `validateOpenApi31` may answer otherwise. |

```bash
zig build interop-openapi              # re-take, write src/spec_oracle_vectors.zig
zig build interop-openapi -- --check   # re-take, compare with the committed file
```

Needs python3 with `openapi-spec-validator`; no network.

**What the replay holds** (2026-10-05, openapi-spec-validator 0.7.1): 102 tables, every
built document accepted by the validator and rebuilt byte for byte (the one table
with a literal `{x}` segment refused with `UnresolvedPathParameter`); 168 mutations
(12 per kind) on which `validateOpenApi31` answers as the validator did, except the
classes SCOPE (an unknown member it does not police: it accepts), VALIDATOR_LAX (a
path parameter missing from its template, forbidden by OAS 3.1 §4.8.12.1 but let
through by the validator: it refuses) and OPENAPI_30 (it accepts 3.1.x only).

# `validate` verification instruments

One differential oracle, run by hand; its answers are frozen in
`src/schema_oracle_vectors.zig` and replayed by `src/schema_oracle_test.zig` in the
module's own lane, with no Python and no bun (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `schema_oracle.py` | Generates rule sets (fixed seed, plus a crafted list) and documents for them, writes the JSON Schema 2020-12 each set must export (the mapping documented above `writeJsonSchema`), and records python-jsonschema's verdict on every document. |
| `ajv_verdicts.js` | ajv 8 (`ajv/dist/2020`, `strict: false`) under bun: the second validator's verdicts on the same schema/document pairs. |

```bash
python3 modules/validate/tools/schema_oracle.py > modules/validate/src/schema_oracle_vectors.zig
python3 modules/validate/tools/schema_oracle.py --check   # re-take, compare with the committed file
```

Needs `bun` with `ajv@8.20.0` in its cache (`bun add ajv@8.20.0` once, anywhere — bun
auto-installs from the cache when no `node_modules` is in reach) and the Python
`jsonschema` package. No network.

**What the replay holds** (2026-10-05, Python 3.14, jsonschema 4.19.2, ajv 8.20.0): 313
rule sets, 2051 documents. The rule set's exported schema must equal the frozen one as a
JSON value; `validateJson` and `validateJsonStreaming` must agree with each other and
answer `want`: the two validators' common verdict (1964 cases), or the verdict a class in
`CLASSES` decided — `PY_DOLLAR` (Python's `$` matches before a final newline; ECMA-262,
which 2020-12 names for `pattern`, does not), `F64_PRECISION` (bounds past 2^53: Python
exact, ajv and the module in doubles), `F64_OVERFLOW` (`1e400` as an integer: ajv's
`Infinity % 1` check calls it one), `BYTES` (byte bounds the schema can only annotate),
`LONE_SURROGATE` (std.json refuses an unpaired surrogate escape). Every class must decide
at least one case.

`format` is left out (anchored on the JSON-Schema-Test-Suite by
`json_schema_format_test.zig`); `custom` and `Pattern.matcher` are code with no schema form.

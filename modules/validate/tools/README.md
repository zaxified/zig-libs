# `validate` verification instruments

Two differential oracles, run by hand; their answers are frozen in
`src/schema_oracle_vectors.zig` / `src/query_oracle_vectors.zig` and replayed by
`src/schema_oracle_test.zig` / `src/query_oracle_test.zig` in the module's own lane, with
no Python, Go or bun (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `schema_oracle.py` | Generates rule sets (fixed seed, plus a crafted list) and documents for them, writes the JSON Schema 2020-12 each set must export (the mapping documented above `writeJsonSchema`), and records python-jsonschema's verdict on every document. |
| `query_oracle.py` | The text path: query strings decoded by three parsers, and values coerced per rule kind judged by pydantic (lax, fed the decoded bytes) with Go and Python's `int()`/`float()` beside it. |
| `go_query/` | Go standard library only: `net/url.ParseQuery` + strconv/math.big verdicts for `query_oracle.py`. |
| `urlsearchparams.js` | bun: WHATWG `URLSearchParams` decoding for `query_oracle.py`. |
| `ajv_verdicts.js` | ajv 8 (`ajv/dist/2020`, `strict: false`) under bun: the second validator's verdicts on the same schema/document pairs. |
| `format_oracle.py` + `go_formats/` | go-playground/validator v10.30.5's own verdicts (`validate.Var(s, tag)`) on 3,289 strings over the 29 formats it has a tag for (crafted edge cases + seeded mutations); every difference from the module is decided by a named class in `CLASSES` (GO DEFECT classes = go breaking the RFC its tag names; the rest = the module's documented profile). Frozen in `src/go_format_vectors.zig`, replayed by `src/go_format_test.zig`. `python3 tools/format_oracle.py > src/go_format_vectors.zig`, `--check` to re-take and compare; needs `go` and the module cache of `go_bench/` (GOPROXY=off). Frozen with `GOTOOLCHAIN=go1.26.0`, the pin `interop.zig` sets: net/url changed between 1.26.0 and 1.26.8 (`http://-[::1]/` parses on .0, not on .8), so a bare `go` of another patch release reports one case stale. |
| `go_casetables/` | Go standard library only: writes `src/case_tables.zig`, the code points Go's `unicode.ToLower`/`ToUpper` change (Unicode 15.0.0 in Go 1.26), which the `lowercase`/`uppercase` formats test against -- go-playground's `s == strings.ToLower(s)` exactly. `cd tools/go_casetables && go run . > ../../src/case_tables.zig`. |
| `bench.zig` + `go_bench/` | The comparative benchmark (`zig build bench-validate`, ReleaseFast, needs go): `parseIntoLeaky` against go-playground/validator v10.30.5 (`json.Unmarshal` + `validate.Struct`), bytes in, validated struct out; 4 body shapes, each with a decode-only twin so the verdict is the net cost of validation. |

```bash
python3 modules/validate/tools/schema_oracle.py > modules/validate/src/schema_oracle_vectors.zig
python3 modules/validate/tools/schema_oracle.py --check   # re-take, compare with the committed file
```

Needs `bun` with `ajv@8.20.0` in its cache (`bun add ajv@8.20.0` once, anywhere — bun
auto-installs from the cache when no `node_modules` is in reach) and the Python
`jsonschema` package. No network.

**What the replay holds** (2026-10-05, re-taken 2026-10-24 with `unique` and numeric `one_of`; Python 3.14, jsonschema 4.19.2, ajv 8.20.0): 317
rule sets, 2075 documents. The rule set's exported schema must equal the frozen one as a
JSON value; `validateJson` and `validateJsonStreaming` must agree with each other and
answer `want`: the two validators' common verdict (1966 cases, re-taken 2026-10-24), or the
verdict a class in `CLASSES` decided — `F64_PRECISION` (bounds and enum entries past 2^53: Python and the
module exact, ajv in doubles), `F64_OVERFLOW` (`1e400` as an integer: ajv's
`Infinity % 1` check calls it one), `BYTES` (byte bounds the schema can only annotate),
`LONE_SURROGATE` (std.json refuses an unpaired surrogate escape). Every class must decide
at least one case. (`PY_DOLLAR`, Python's `$` matching before a final newline, is gone
since 2026-10-24: the export ends a pattern with `(?![\s\S])`, the end of the text in every
regex dialect, so both validators agree.)

`format` is left out (anchored on the JSON-Schema-Test-Suite by
`json_schema_format_test.zig`); `custom` and `Pattern.matcher` are code with no schema form.

## Query oracle

```bash
PY=~/.local/share/zig-libs/oracle-venvs/fastapi/bin/python   # any Python with pydantic 2
$PY modules/validate/tools/query_oracle.py > modules/validate/src/query_oracle_vectors.zig
$PY modules/validate/tools/query_oracle.py --check
```

Needs pydantic (the FastAPI oracle venv, kept outside the repo), `go` (standard library
only, no module downloads) and `bun`. No network.

**What the replay holds** (2026-10-06, Python 3.14, pydantic 2.13.5, go1.26.0, bun 1.3.12):
39 queries whose first value of field `v` must decode as `parse_qsl`, `net/url` and
`URLSearchParams` decode it, and 336 values × 12 rules that `validateQuery` must accept, or
refuse with pydantic's error code among its errors. Classes where they split:
`GO_DROPS_BAD_ESCAPE`, `GO_DROPS_SEMICOLON`, `WHATWG_REPLACES` (decoding), `PYDANTIC_STRIPS`,
`INT_FRACTION`, `F64_PRECISION` (coercion) -- each described in the script and pinned to at
least one case. The run before the fixes is the negative control: it reported the five
defects listed in the module CHANGELOG (2026-10-06).

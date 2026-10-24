# validate — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-24** — **Fix** (review 2026-10-24, grade-1 wave 6):
  - **Exact integer comparisons:** an integer is held to `min`/`max` exactly (`9007199254740993` passed `max = 9007199254740992` as f64). Cross-field comparisons are exact for integers past i64 and against floats (`18446744073709551615` `eq_field` `18446744073709551614` passed).
  - **Export:** a suffix or charset `pattern` ends with `(?![\s\S])` instead of `$`, which Python `re`, PCRE, Java and .NET let match before a final newline. `required_if`/`required_unless` entries naming one sibling with two values are both exported (the second was dropped).
  - **Smaller fixes:** an `.any` rule on a hand-built unparseable `number_string` reports a type error instead of reaching `unreachable`. Duplicate keys in a large object are found through a set on the streaming path instead of a quadratic scan. `parseIntoLeaky` decodes a `[:0]const u8` field (it did not compile).
  - **Consumer-visible:** exported patterns change text, and integer bounds past 2^53 now refuse what they used to pass.
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** mutation audit 120/131, 11 equivalent, 14 tests added (section "pinned by the 2026-10-24 mutation audit"). Card: fastest 3.97× garde on `nested` (P stays 2; see Backlog).
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** `tools/interop.zig` re-takes both oracles (`zig build interop-validate [-- --check]`). Their `F64_PRECISION` class is decided by the exact comparison now, and `PY_DOLLAR` is gone. `tools/rust_fast_bench` (garde 0.23.0, validator 0.21.0) adds the fastest-in-the-field side to `bench-validate`. README: duplicate keys are refused, not "last wins".

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-19** — **NO CONSUMER-VISIBLE CHANGE:** Deprecated std names replaced by their Zig 0.17 spellings (`mem.indexOf*` -> `mem.find*`, `fmt.bufPrint` -> `mem.print`, `fmt.allocPrint(a, …)` -> `a.print(…)`, `bufPrintSentinel` -> `mem.printSentinel`, `@intFromEnum` -> `@backingInt`); the old names are aliases, so behaviour is identical.

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC brought up to Zig 0.17.0 (version statements, snippets, measurement labels).

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** tools ported to Zig 0.17.0 (compile only): `tools/bench.zig`: struct `.fields[0].name` -> `field_names[0]`.
- **2026-10-18** — Ported to Zig 0.17.0. Non-mechanical: private `StructField`/`structFields` shim over `field_names`/`field_types`/`field_attrs` for `rulesFor` and `parseQueryLeaky` (struct `.fields` is gone); `std.heap.stackFallback` -> `BufferFirstAllocator` over a stack buffer (2 sites); the `checkAllAllocationFailures` tests wrap their allocator in a resize-refusing `NoResize` (zig 0.17.1: 7c793c2); `validateParams`' param lookup `get` must now be `pub` (`@hasDecl` sees only pub decls; compile error text says so, `validate_rules` was already documented as `pub`). `max_body_bytes` (`readBody`): 0.17 `allocRemaining(.limited(n))` accepts exactly n bytes = the documented cap; new test pins n accepted, n+1 -> 413.
- **2026-10-17** — `date`/`date-time` checks and instant comparison use `datefmt.daysInMonth`/`ymdToEpochDay` (new direct dep `datefmt`, already in the closure via `http`) instead of this module's own civil-calendar helpers. No behaviour change.
- **2026-10-11** — **Scope parity with go-playground/validator v10.30.5 (S3 -> S2)**, no breaking
  change: every addition is a new decl or a field with a default that keeps the old behaviour.
  - **Cross-field rules**: `Rule.cross: []const Cross` (`CrossOp`: `eq_field`, `ne_field`, `gt_field`,
    `gte_field`, `lt_field`, `lte_field`, `required_if`, `required_unless`, `required_with`,
    `required_without`), on the tree path, the streaming walker (it captures the members the rules name
    while the object goes by and settles them at the object's end, next to `required`) and the typed
    paths (`T.validate_rules`). Codes `field_mismatch`, `field_equal`, `greater_than_field`,
    `greater_than_equal_field`, `less_than_field`, `less_than_equal_field`; the presence ops report
    `missing`. `writeJsonSchema` exports `required_with` as `dependentRequired` and the other presence ops
    as `allOf` items (`if`/`then`, `anyOf`); the comparison ops have no 2020-12 form and are not exported.
  - **Array roots**: `validateJsonRoot` / `validateJsonRootStreaming` (a root `Rule`, errors at
    `[i].field`), `rootRuleFor`, `writeJsonSchemaRoot`, and `parseInto` / `parseIntoLimited` /
    `parseIntoLeaky` / `TypedBody` / `writeJsonSchemaFor` accept `[]const T` and `[N]T`. Limits apply.
  - **22 formats** (`Format`): `uuid3` `uuid4` `uuid5` `uuid7` `uuid_rfc4122` `http_url` `https_url`
    `base64` `base64_url` `base64_raw_url` `hex` `e164` `alpha` `alphanumeric` `numeric` `ascii`
    `lowercase` `uppercase` `jwt` `semver` `cidr` `mac`, each citing the go-playground baked-in it follows.
  - `tools/bench.zig` + `tools/go_bench` (`zig build bench-validate`): `parseIntoLeaky` against
    `json.Unmarshal` + `validate.Struct`.
  - tests: cross-field on both paths, array roots, a truth table per new format, a `cross` fuzz
    harness (`VALIDATE_FUZZ`, tree == streaming, also as a root array).
- **2026-10-09** — tests: deterministic fuzz driver `VALIDATE_FUZZ` over the existing harnesses (`json`, `streaming`, `format`).
- **2026-10-06** — **Anchoring: query decoding + coercion oracle** (`tools/query_oracle.py`,
  `src/query_oracle_test.zig`): Python `parse_qsl`, Go `net/url` and WHATWG `URLSearchParams` judge the
  decoding; pydantic 2.13.5 (lax, fed the decoded bytes) judges the coercion and the error code, with
  Go's strconv and Python's `int()`/`float()` as tie-breakers. Decoding agreed. **5 DEFECTS fixed** in
  `validateQuery` / `validateParams` / `parseQueryLeaky`:
  - **BEHAVIOURAL:** a NaN (`x=nan`) fails `min`/`max` (both); every comparison with NaN was false, so
    it passed any bound.
  - **BEHAVIOURAL:** an integer past i64 coerces (as `.number_string`, bounds in f64, like a JSON
    integer); it was `int_parsing`, so a `u64` field of `parseQueryLeaky` refused 2^63..2^64-1.
  - **BEHAVIOURAL:** `1__0` is `int_parsing`, `0x10` / `0x1p3` are `float_parsing` (`std.fmt` took them).
  - **BEHAVIOURAL:** a `.string`/`.any` value that is not UTF-8 is `string_unicode`; it passed unless the
    rule had a length bound, and with `one_of`/`pattern` it got `enum`/`string_pattern_mismatch`.
  - **BEHAVIOURAL (looser):** bool coercion takes pydantic's whole vocabulary, case-insensitive:
    `t`/`y`/`yes`/`on` and `f`/`n`/`no`/`off` besides `true`/`1`/`false`/`0` (HTML checkboxes send `on`).
  Judged and kept: whitespace around a number and `5.0` as an int stay refused (pydantic takes them,
  Go's strconv and the JSON grammar do not). Evidence MIXED → EXTERNAL.

- **2026-10-05** — **Anchoring: python-jsonschema + ajv oracle** (`tools/schema_oracle.py`,
  `src/schema_oracle_test.zig`): 313 rule sets must export the frozen schema, and 2051 documents must
  get both validators' verdict on it, on the tree and the streaming path. **4 DEFECTS fixed**, each a
  place where the validator was looser than its own exported schema:
  - **BEHAVIOURAL:** `.any` with `one_of` or a `literal` pattern now refuses a value that is not a
    string (`enum` / `string_pattern_mismatch`); it accepted `5`, `true`, `null`, `[]`, `{}`.
  - **BEHAVIOURAL:** an integer literal beyond i64 is an integer (`.int`), as `1e23` always was; it was
    `int_type`, which also made `parseInto` refuse every `u64` above 2^63-1. `rulesFor` now bounds
    integer types wider than 53 bits by their width too (nearest f64), so `1e20` into an `i64` is a
    pathed `less_than_equal`, not a decode failure; `writeJsonSchemaFor` states those bounds too
    (an `i64` field gains `minimum`/`maximum` ±9.223372036854776e18).
  - **BEHAVIOURAL:** `Pattern.charset` compares code points, not bytes: `â` no longer passes the set
    `¢ü`; a string that is not UTF-8 (possible only on the query path) matches no set. ASCII sets
    answer as before.
  - `writeJsonSchema`: a rule with `allow_null` and `one_of` / a `literal` exports one `enum` that
    lists null too (the null was refused by the exported `enum`/`const`).

- **2026-10-04** — **Tests:** mutation run (58 schemata mutants, 54 killed, 4 equivalent).
  New tests pin the inclusive lower bounds (`min`, string and array `min_len`) at their exact
  edge on the tree and the streaming path, an integer literal beyond i64 failing `int_type`,
  the 253-byte hostname limit (254 rejected), and query `"1"` coercing to `true`. No code change.

- **2026-09-30** — `Pattern.matcher` (new `Matcher`): a string `pattern` checked by a caller-supplied
  function (a regex from any library, or a hand-written test) with the expression's source text carried
  for the exported JSON Schema (`"pattern": source`) and the `string_pattern_mismatch` message. ⚠ An
  exhaustive `switch` over `Pattern` needs the new arm.

- **2026-09-28** — **New: `parseQueryLeaky(T, arena, query, limits)`** — the typed query style: a
  query string decoded into struct `T`, validated against `rulesFor(T)` plus `T.validate_rules`
  (a declared rule may name a parameter `T` does not decode; it is checked all the same), with
  `validateQuery`'s decoding and coercion. Fields: bool, integers, floats, enums, `[]const u8`,
  `[N]u8`, `?U` of those -- anything else is a compile error; a field with a default is optional.
  One walk over the query; keys are compared as they decode, so `validateQuery` no longer
  allocates a decoded copy of every key either. (qap M11.7.)

- **2026-09-26** — **`parseIntoLeaky` validates and decodes in one tokenization.** The streaming
  walker is push-shaped now (an explicit frame stack fed whole tokens), and `std.json`'s typed
  decoder pulls the tokens through a tap that feeds each to it, with the structural limits
  checked on the way: one pass over the body where there were three (limit pre-scan, validation
  walk, decode). A document the decoder refuses, or the walker stops (duplicate key, a limit),
  takes the old multi-pass path, so every invalid document is reported exactly as before; the two
  paths are pinned against each other on the corpus and in the differential fuzz target. A 33-byte
  two-field body: 7,357 → 5,034 instructions per parse (bare `parseFromSliceLeaky`: 2,221).
  `validateJsonStreaming` runs on the same walker. No API change. (SPEC backlog, found by qap.)

- **2026-09-22** — **New: `writeJsonSchema(rules, w)` / `writeJsonSchemaFor(T, w)`** — the
  rules as a JSON Schema 2020-12 document, for an API description (OpenAPI 3.1 embeds 2020-12
  as is). Faithful mapping: lengths in code points (`minLength`) and items (`minItems`), `.any`
  states both, `.int` → `integer` (accepts `1.0`, as the validator does), `allow_null` → a type
  array, `one_of` → `enum`, `format` → the 2020-12 names, patterns → `const` or an anchored,
  escaped ECMA-262 `pattern`, two rules for one field → `allOf`, `T.validate_rules` → `allOf` of
  both sets. Byte bounds have no keyword: `x-minBytes`/`x-maxBytes` plus the code-point bounds
  they imply (looser, never stricter); `custom` → `x-custom`. Checked against Python `jsonschema`
  4.19.2 on 33 bodies: 32 agree, the 33rd is that byte-bound looseness; pinned as a golden.

- **2026-09-22** — **`Limits.max_errors`: a caller can lower the error cap.** The
  report keeps at most `max_errors` errors (default and ceiling: the module's
  1000) and builds none past it; 0 counts as 1, so an invalid document is never
  reported valid. Honoured by `validateJsonLimited`, `parseIntoLimited` and the
  streaming path. Why: a caller decoding into a fixed buffer (qap's typed bodies)
  found that aggregating the errors of a body wrong everywhere costs more than
  decoding it — 1500 wrong items overflowed a 4 KiB buffer, so the answer read
  "too large" instead of "invalid". Test pins each path, the 0→1 rule and the
  ceiling.

- **2026-09-22** — **New streaming path: `parseIntoLeaky(T, arena, body, limits)` and
  `validateJsonStreaming(gpa, body, schema, limits)`** — the rules, codes and messages of
  `parseIntoLimited`/`validateJsonLimited` without building a `std.json.Value` tree. The tree
  costs 30–60× the body; the streaming path ~1.5× + ~2 KiB (smallest FixedBufferAllocator for a
  16.5 KiB body: 955 KiB → 25 KiB; 118 B body: 4.4 KiB → 704 B), so a server can decode typed
  bodies into a fixed per-request buffer. Scalars go through the same `checkRule`; containers are
  walked from the scanner's tokens; only a container with a `custom` rule is materialized. The
  decoded `T` is allocator-leaky and borrows unescaped strings from `body`. Errors come in document
  order; the error set equals the tree path's — pinned by a differential fuzz target and a
  hand-written edge set (escaped/duplicate/nested keys, malformed values inside a duplicate,
  number_string, fixed byte arrays). Also: `SPEC.md` claimed duplicate keys resolve "last wins";
  they are refused (`DuplicateField` → `json_invalid`), on both paths.

- **2026-09-22** — **FIX (memory safety): `parseInto`/`parseIntoLimited` freed
  the validation arena twice when the decode into `T` ran out of memory.** On the
  success path the error builder is aborted before `std.json.parseFromValue`
  runs, but its `errdefer b.abort()` was still armed, so an `OutOfMemory` from the
  decode deinitialized the same arena again — a double free on a heap allocator
  (heap corruption in ReleaseFast), an assertion on a `FixedBufferAllocator`.
  Reachable by any caller whose allocator can fail (a bounded arena, a request
  budget). Found by a sizing probe on a `FixedBufferAllocator`. New test sweeps
  every allocation failure point of `parseIntoLimited`, `validateJsonLimited` and
  `validateQuery` with `checkAllAllocationFailures` (no leak, no double free);
  red on the old code.

- **2026-09-22** — **Errors as RFC 9457 problem details, and `validateParams`
  over any lookup.** New `Report.writeProblem(w, http.problem.Problem)` and the
  standalone `writeErrorsProblem(errors, problem, w)`: an
  `application/problem+json` body whose `errors` extension member is the same
  `[{path,code,message},…]` list `writeJson` writes. `validateParams` now takes
  `params: anytype` — anything with `get(name: []const u8) ?[]const u8`, by value
  or pointer — instead of only `*const router.Params`, so a server whose params
  type is its own can use it; existing `&router.Params` callers compile
  unchanged, and a type without such a `get` is a compile error that says so.
  The middleware still answers 400 with `application/json` (see SPEC backlog).

- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/json_schema_format_test.zig` and `src/json_schema_format_vectors.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-09-07** — **Test-only: neither fuzz target had a corpus, so each ran
  exactly ONE input for ever, and `fuzzValidateFormat`'s was `.email` with the
  empty string.** Outside `--fuzz` the runner feeds `options.corpus` plus one
  round of `in = ""`, and every `Smith` draw on an exhausted input returns its
  minimum. So `fuzzValidateJson`'s opening `smith.value(bool)` was false, every
  per-field `smith.value(bool)` was false too, and the body it assembled was
  `"{}"` — the type gate, the format and pattern checks, the min_len/max_len
  bounds and the nested object/array walk, which the harness's own comment
  lists as the whole reason the shape generator exists, had never run.
  `fuzzValidateFormat` was worse: `smith.value(Format)` returned the first enum
  value on every input, so **eleven of the twelve formats had never been called
  at all**. Both now draw once with `smith.slice` and read their choices from
  the drawn octets through `testkit.fuzz.Cursor`, with seeds whose first octet
  selects "the rest is the body/string verbatim" or "the rest is a script".
  Measured 2026-09-07: **JSON target 1 body and 2 violations before; 17 bodies
  over 692 octets, 2 of them valid, 23 violations after. Format target 1 format
  and 0 non-empty strings before; all 12 formats, 21 non-empty strings and 12
  accepted after.** ⭐ The JSON guard pins the violation COUNT rather than
  acceptance, because acceptance is wrong at both ends here — `{}` is refused
  for two missing required fields, and a fully valid body is refused by nothing,
  so a corpus stuck at either extreme reads as a clean pass.

- **2026-09-02** — **Audit (drift campaign): 4 MEDIUM, 3 LOW.** No memory-safety defect and no
  mode difference anywhere; every finding is about a rule that did not do what it says.
  **MEDIUM, BEHAVIOURAL — `kind = .any` no longer voids every constraint.** `.any` is the
  DEFAULT `kind`, and it used to skip the whole constraint switch — so one omitted
  `.kind = .string` turned a rule carrying `required`, `format`, `min_len`, `max_len`, `one_of`
  and `pattern` into a silent no-op (`ok() == true` on input violating all six), with no comptime
  or runtime signal. It now means "any TYPE is acceptable": whatever type arrives is held to the
  constraints the rule states. A rule with no constraints is unaffected, which is what `.any` was
  for. **A validator that fails open by default is worse than no validator.**
  **MEDIUM — new `min_bytes`/`max_bytes`, and the derived `[N]u8` rule uses them.** When lengths
  became code points, `rulesFor(struct { fixed: [16]u8 })` kept emitting `min_len = max_len = 16`
  — 16 CHARACTERS against a decoder that fills 16 BYTES. `"éééééééé"` (16 bytes, 8 code points)
  decodes perfectly and was REJECTED; a 16-code-point/17-byte string passed the rule and then
  failed inside `parseFromValue` as an unpathed root `invalid`. `rulesFor` is `pub`, so the
  false-yes is reachable without the decode.
  **MEDIUM — `max_errors` now bounds the WORK, not just the list.** The cap was checked inside
  `append`, after `appendf` had already formatted the message, and `indexPath` allocated a path
  for every array element regardless of outcome. Measured: a 996 KiB body of 340 000 nodes — all
  of it inside the DEFAULT `Limits` — built 339 000 messages nobody could read and held an
  **18 802 KiB** report arena for the 1000 errors it kept. Pinned by a counting allocator with a
  4 MiB ceiling; the old code overshoots it by 4.7×.
  **MEDIUM — three of the four `Limits` defaults SPEC names as the security control had nothing
  pinning them.** Raising `max_array_elements` 10 000→1e8, `max_object_members` 1 000→1e8 or
  `max_total_nodes` 1e6→1e11 each left the suite fully green; the one test that claimed to cover
  this exercised `max_depth` alone. The defaults worked — nothing would have noticed them
  stopping.
  **LOW — docs:** `README` and `Rule`'s struct doc still said string lengths are BYTES, which is
  what made the `[N]u8` defect easy to miss; the README's RFC list now names the one place
  `date`/`time`/`date_time` are laxer than RFC 3339 (the optional offset).
  **LOW — `isEmail`'s documented 254-byte ceiling** and **the offset-optional date-time profile**
  are pinned. Removing the email cap left the suite green while 255–318-byte addresses became
  acceptable; the date-time choice had no corpus case at all in either direction.
  Ledger: `~/CML/20260931-zig-libs-audit/validate.md`.

- **2026-07-28** — Security audit: the module's untrusted-input surface gained fuzz
  harnesses — `fuzzValidateJson` and `fuzzValidateFormat` (the latter across all 12
  formats) — which it had none of, unlike the sibling wire parsers. Tests only.
- **2026-07-21** — **BEHAVIOURAL, not breaking** — two audit findings fixed. `min_len` /
  `max_len` counted **bytes** while the emitted message said "characters", the module doc
  said "string chars" and the modeled reference (pydantic v2) counts code points; they now
  count Unicode code points, and a string carrying invalid UTF-8 fails closed with
  `string_unicode` when a length rule applies. Separately, `numValue` did `parseFloat(s)
  catch 0` on a `.number_string`, so a value that cleared the JSON number grammar but
  failed to parse was silently compared against `min`/`max` as `0`; it now returns `?f64`
  and the call site emits a validation error instead.
- **2026-07-19** — Security audit (HIGH, reproduced). Error aggregation was **O(n²)**:
  `Builder.append` linearly scanned every error collected so far to dedupe on each append,
  so a request body that complies with the default structural limits (≤10 000 array
  elements) but fails a per-element rule burned ~196 ms of CPU in ReleaseFast and 3.2 s in
  Debug, scaling quadratically — a remotely triggerable CPU-exhaustion DoS against any
  schema with a constrained array or object field. The per-append scan is gone (the
  single-pass validator produces no duplicates), the one genuine duplicate source is
  deduped once via `dedupeFrom`, and a hard `max_errors = 1000` cap bounds both sides, so a
  report is now linear and capped rather than quadratic and unbounded. The audit raised
  four findings in total and all four were fixed; the other three are the entries above.

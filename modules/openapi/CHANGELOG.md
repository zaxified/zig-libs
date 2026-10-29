# openapi — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-29** — **NO CONSUMER-VISIBLE CHANGE (one test case added):** Delta audit of the no-panic sweep: 13 schemata mutants over the sweep diff (depth cap and its boundary, depth walk without arrays, validateRefs pushes, `$id` skip, first-entry-wins, operationId counter start, query `required` dedup, parameter/template checks): 12 killed on the first run; the survivor (a `$ref` entry's name/in no longer counted as an earlier parameter) became a case in the OA-3 test. 13/13. Card A1 again.
- **2026-10-29** — **CONSUMER-VISIBLE (no-panic sweep):** JSON text taken from the caller (request/query/parameter/response/named schemas, examples) nested deeper than 128 is refused with the existing `Invalid*Schema` / `InvalidExample` errors; deeper text overflowed the stack (HIGH, OA-4) and past 256 tripped the JSON writer's assert. `validateOpenApi31` walks `$ref`s iteratively (a 500 000-deep document overflowed the stack, HIGH, OA-1); `$ref` resolution and the checker's parameter and path-template checks are hash lookups instead of quadratic scans (30 000 refs took 49 s, OA-2/3); five generator loops over route tables made linear (OA-5).
- **2026-10-23** — **BREAKING:** `validateOpenApi31(gpa, doc)` takes a scratch allocator (no
  consumer outside the module calls it); `ConformanceError` gains `DuplicateOperationId` and
  `OutOfMemory`. Grade 1 re-audit (review + 95/95 mutants), fixes: duplicate `operationId`s
  (`/a/b` and `/a_b`, `/users` and `/users/`, `/u/:id` and `/u/id`) — a repeat now gets the
  smallest free `_<n>` suffix, ids without a collision unchanged, and the checker refuses
  duplicates; `Endpoint` no longer caches a transient `OutOfMemory`; a schema that is JSON but not a
  JSON Schema (`null`, `5`, `[]`) is the field's typed error; a `query_schema`'s own
  `properties`/`required` count beside its `allOf` (`validate.writeJsonSchemaFor` types with
  cross-field rules documented no query parameters), a `$ref` part is `InvalidQuerySchema`;
  `Generator.write`/`writeRoutes` write the self-checked document or nothing (were streaming,
  unchecked); `$ref` inside a subtree with its own `$id` is not resolved against the document,
  `%XX` in a pointer is decoded; the docs page escapes `Endpoint.path` in its script; no cap on
  the duplicate-status / duplicate-capture checks. Lead on the card: FastAPI drops a reachable
  route from its document on a path collision (`tools/fastapi_lead/probe.py`).

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** tools ported to Zig 0.17.0 (compile only): `tools/interop.zig`: `dupeZ` -> `dupeSentinel`, `Ast.parse` takes `.{ .mode = .zig }`.
- **2026-10-18** — Ported to Zig 0.17.0. method loop uses `@typeInfo(http.Method).@"enum".field_values` (`.fields` is gone). No behaviour change.

- **2026-10-12** — CONNECT and extension-method (`.other`) routes (http R9) stay out of the
  document: an OpenAPI 3.1 Path Item has no field for them. TRACE routes are operations.

- **2026-10-11** — tests: fuzz harnesses `build` (generator: `buildRoutes` and `writeRoutes` agree,
  a rebuild is byte-identical, the output re-parses and passes the checker, no non-UTF-8 accepted)
  and `spec` (`validateOpenApi31` on raw bytes and on damaged generated documents), with the
  deterministic driver `OPENAPI_FUZZ`; `zig build check-fuzz` was red on openapi since 2026-10-11.
- **2026-10-12** — docs: backlog item "move `route_extras` onto `RouteDoc`" rejected with the reason (keeps `router` free of OpenAPI-only fields). No code change.
- **2026-10-12** — **Scope core -> parity with FastAPI 0.142.** Additive `Info` members, all off by
  default (output byte-identical when unused): `servers`; `schemas` (named-schema registry ->
  `components.schemas`, `schemaRef(name)` for the `$ref` text; same name + different body is
  `error.SchemaConflict`); `security_schemes` (apiKey in header/query/cookie, http basic/bearer,
  OAuth2 flows, openIdConnect) and `security`; `route_extras` (per route by method + pattern:
  header and cookie parameters, request/response `example`, per-operation `security`).
  `validateOpenApi31` now resolves every local `$ref` (`error.DanglingRef`) and checks servers,
  scheme shapes, component names and security uses (`UnknownSecurityScheme`, `InvalidSecurityScheme`,
  `InvalidServer`, `InvalidComponentName`). Tests in `src/parity_test.zig`.

- **2026-10-10** — Card Performance `n/a` with the reason (no timeable reference implementation). Docs only.

- **2026-10-07** — Follows `router`'s `{name}` captures: a whole-segment or in-segment capture
  (`/files/{name}.{ext}`) is already an OpenAPI template and gets its path parameters (via
  `router.PatternCaptures`); a bare `*` becomes `{*}`; `operationId` drops template braces
  (`get_files_name.ext`). The spec oracle re-taken with such patterns drawn (102 tables, all
  built and accepted; FastAPI maps them the same). The literal-`{x}` table it used to hold is
  gone — `router` no longer registers a literal brace.
- **2026-10-07** — A `{name:regexp}` capture (router's chi-style constraint) becomes the plain
  template `{name}`: the constraint is dropped (OpenAPI's `pattern` speaks ECMA-262, not RE2).
  Spec oracle re-taken with constrained captures drawn.
- **2026-10-05** — **Anchoring: openapi-spec-validator oracle** (`tools/spec_oracle.py`, `tools/interop.zig`,
  `src/spec_oracle_test.zig`): 102 route tables built through a real router must give the documents the
  validator accepted; 168 mutated documents must get the validator's verdict from `validateOpenApi31`; and FastAPI,
  given the same routes, must produce the same path templates, methods and path parameters (it does, on every
  table). Anchor grade MIXED → EXTERNAL.
  - **DEFECT fixed, BEHAVIOURAL:** a route with a literal `{x}` static segment produced a document with a
    template variable and no parameter, which every validator refuses; `build` now fails with
    `error.UnresolvedPathParameter` (exclude such a route with `Info.include`).
  - `validateOpenApi31` checks parameters: path template against path parameters both ways, `required: true`
    on path parameters, duplicates, `in`, exactly one of `schema`/`content`; and `responses` keys. ⚠ New
    `ConformanceError` (and so `BuildError`) members: `UnresolvedPathParameter`, `UndeclaredPathParameter`,
    `OptionalPathParameter`, `DuplicateParameter`, `InvalidParameter`, `InvalidResponseKey` -- an exhaustive
    `switch` needs the new arms.

- **2026-10-04** — **Tests:** mutation run (35 schemata mutants, 34 killed, 1 equivalent). New
  tests: a non-UTF-8 response description is `InvalidUtf8`; `validateOpenApi31` refuses a
  non-string response `description` and accepts non-operation Path Item members. No code change.

- **2026-09-28** — **Query parameters.** `RouteDoc.query_schema` (an object schema, or `allOf` of
  them -- what `validate.writeJsonSchemaFor(T)` writes, `allOf` when `T` declares
  `validate_rules`) becomes one `in: query` parameter per property, after the path parameters,
  `required` when any part requires it, the property's schema as its `schema` (`allOf` of them when
  several parts describe it). A schema that does not name parameters that way (not an object,
  `properties` not an object, a `required` that is not an array of described names) → new
  `error.InvalidQuerySchema`. The output
  passes `openapi-spec-validator --schema 3.1` (verdict frozen next to the test).

- **2026-09-22** — **Response bodies and bearer auth.** A `RouteDoc.Response` with a `schema`
  is emitted with `content."<media_type>".schema` (validated and re-emitted like
  `request_schema`; malformed text → new `error.InvalidResponseSchema`). `Info.bearer_auth`
  declares `components.securitySchemes.bearerAuth` (`http`/`bearer`) and requires it on every
  operation. New golden accepted by `openapi_spec_validator` 0.7.1.

- **2026-09-22** — `Generator.buildRoutes` / `writeRoutes`: the same document from a plain
  `[]const router.Route` instead of a `*const router.Router`, for a server whose table is a comptime
  `router.Static` or its own. `build`/`write` now delegate to them; their output is unchanged.
- **2026-09-11** — **BEHAVIOURAL + API change (user-approved, Q1/Q7/Q8/Q9 — `QUESTIONS-ROUND-2.md`),
  `example-apps/http-service` checked by hand, no change needed** — A1/openapi.md F4, F5, F9, F10,
  F11, F13 closed (F12 closed as a strict subset of F9).
  - **F4 (norm: JSON text MUST be valid UTF-8, RFC 8259 §8.1):** every `Info`/`RouteDoc` string
    field and every route pattern is now UTF-8-validated BEFORE any output is written; a bad byte
    fails the whole build atomically with a new `error.InvalidUtf8` instead of `std.json.Stringify`
    silently turning a `[]const u8` field into a JSON array of byte values, or an `objectField` key
    going out raw and unparseable. Falsifies a prior PASS-log claim ("route metadata cannot break
    the document structure").
  - **F5 (norm: a dispatchable route must not silently disappear):** two different routes that
    convert to the same `(path, method)` — e.g. `/f/:p` and `/f/*p`, both legal, independently
    dispatchable `router` routes, both becoming `/f/{p}` — used to silently keep only the first and
    drop the second's documented operation without a trace. Now a new `error.PathCollision`.
  - **F9 (norm: a checker that exists should run):** `Generator.build` now parses its own output
    back and runs its own `validateOpenApi31` on it before returning — the checker already caught
    this class of defect in the module's own tests, but never ran on a document before it reached a
    caller. Costs one extra parse, paid once per `Endpoint`'s lifetime (already cached since F1).
    **Closes F12** (empty `info.title`/`version` silently emitted) as a strict subset.
  - **F10 (doc fix, no code change):** `Endpoint`'s own doc comment claimed the document "still
    reflects everything registered by the time the first request arrives", inviting registration
    concurrent with early requests. `r.routes()` is read once, unsynchronized — a route added
    concurrently with (not just before) that read races `Router`'s own backing slice. Brought in
    line with the ALREADY-correct precondition `Generator.build`'s own comment stated ("the Router
    must be done registering routes... a built Router is immutable, so this is safe from any
    thread") and with `router/SPEC.md`'s "building is single-owner" phase discipline — not new
    synchronization, which would be `router`-side work outside this fix's scope.
  - **F11 (additive, P3):** new `Info.include: ?*const fn (router.Route) bool`, `null` by default —
    return `false` to omit a route from the document entirely (FastAPI's `include_in_schema=False`,
    utoipa's opt-in `#[utoipa::path]`). Applied before anything else touches a route.
  - **F13 (norm + Q6-unblocked verification):** `//x` as a `paths` key is closed as a side effect of
    `router`'s own F11 fix (such a pattern can no longer be registered at all). `operationId` — the
    other half — is now always emitted, deterministically (`(method, converted_path)`, unique by
    construction via F5's collision guard). Re-verified against the real `openapi-spec-validator`
    (installed by the user 2026-09-11 for this): the golden document, `operationId` included, is
    still `OK`/exit 0; a document with two operations sharing one `operationId` is REJECTED (OAS
    3.1 §4.8.10), confirming the uniqueness property is real, not assumed.
  - All four "external anchor" documents re-verified against the real, installed
    `openapi-spec-validator` (frozen verdict updated from 2026-08-01 to 2026-09-11).
- **2026-09-10** — **BEHAVIOURAL, not breaking:** Two `RouteDoc.Response`s sharing a `status`
  used to both get written into the generated document, producing a duplicate JSON object
  key that `std.json` — the parser this module uses everywhere, including its own docs page
  — refuses to re-read (`error.DuplicateField`), contradicting this module's own doc comment
  ("duplicate JSON keys are never emitted"). Now dedupes, first registration wins — same rule
  `writePathParameters` already applies to a duplicate path-parameter name (F6). The pre-fix
  output was not valid JSON at all, so no well-formed behavior is being taken away (wave-2
  audit finding F3).
- **2026-09-10** — **BEHAVIOURAL, not breaking:** A `/openapi.json` request that hits a
  route with a malformed `request_schema` used to redo the FULL document build, under a
  pure spinlock, on every single request forever (compounding to O(N²) CPU under
  concurrency — one malformed schema could cost tens of seconds of CPU for a handful of
  unauthenticated requests). Both the successful AND the failed build are now cached, and
  the build runs outside the lock, so this degrades to "the same error, cheaply" instead
  of "the same expensive failure, forever". Path/method grouping is now O(routes) instead
  of O(routes²) (unchanged output, just faster on large route tables). A route pattern
  that captures the same parameter name twice no longer emits a duplicate OAS parameter
  entry. The response now carries a strong `ETag`; a matching `If-None-Match` gets `304`
  instead of the full body. README/SPEC.md corrected to describe the actual
  build-once-and-cache concurrency model (they still described the pre-2026-08
  per-request-regeneration behavior).
- **2026-09-09** — Licensing correction, no code change. `NOTICE` said the reproduced
  OpenAPI `webhook-example.json` "adds no condition beyond MIT's own" and pointed the
  reader at upstream's `LICENSE` file — a file that is not in this tree, so a consumer
  who received only zig-libs got no copy of the licence at all. Apache-2.0 §4(a) is now
  discharged by reproducing the License in full. §4(b) records that the document is
  byte-for-byte unmodified; §4(d) records that upstream ships no `NOTICE` (HTTP 404,
  re-verified 2026-09-09), so nothing propagates.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on FastAPI auto-docs
  (Python), utoipa (Rust) (design reference, not a test anchor).
- **2026-07-03** — New module: OpenAPI 3.1 spec generated from the route table +
  `/openapi.json`.

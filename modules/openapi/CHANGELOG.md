# openapi — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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

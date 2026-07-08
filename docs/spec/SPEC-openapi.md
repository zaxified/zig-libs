# SPEC — `openapi`

**Purpose** — OpenAPI 3.1 document generation from a `router` route table, plus a ready-made
`GET /openapi.json` endpoint middleware. "Self-documentation": the spec is derived from the live
`Router.routes()` table and per-route `RouteDoc` metadata (`Router.addDoc`), so the docs cannot
drift from the code. Closes the Web-service/API cluster.

**Model after / Seed** — Clean-room; no seed project, no third-party code. Design references
(behavior only, no source consulted or copied, per `NOTICE`): FastAPI (the emitted document shape —
operation key order, path-parameter objects, the default `"Successful Response"` 200) and utoipa
(Rust; route-metadata→spec mapping). Document format per the OpenAPI Specification 3.1.0 (OpenAPI
Initiative).

**Design & invariants**
- **Two layers.** `Generator` walks `Router.routes()` and emits a valid OpenAPI 3.1 JSON document
  (`openapi: "3.1.0"`, `info` from `Info`, `paths` with router patterns converted to templates —
  `:id` → `{id}`, `*rest` → `{rest}` — methods grouped per path). `Endpoint` is an *intercepting*
  `router.Middleware` (the `metrics.Endpoint` pattern, needed because `router.Handler` is a
  stateless fn pointer and cannot close over state) serving the generated document on
  `GET /openapi.json`; it must be registered *before* the routes it documents (chi's rule) but
  generates the spec fresh per request, so it still sees routes registered after it.
- **Deterministic, minified output:** paths in first-registration order, methods per path in
  `http.Method` declaration order, fixed key order inside every object, no whitespace. Two runs over
  the same router produce byte-identical documents.
- **Documented FastAPI-shape compromises:** path parameters are always `required: true` with
  `schema: {type: "string"}` (the router only captures raw path bytes, no richer typing); a
  `*wildcard` segment becomes a plain `{param}` since OpenAPI has no cross-segment template (FastAPI's
  own `:path` converter makes the same compromise). Undocumented routes get a minimal operation with
  the default `responses: {"200": {"description": "Successful Response"}}`. `operationId` is
  deliberately omitted — a fn-pointer route table has no stable name to derive one from. The
  implicit HEAD→GET auto-route and 404/405 dispatch fallbacks are not emitted; they are dispatch
  behavior, not operations.
- **`RouteDoc.request_schema`** (JSON Schema as text) is parsed and re-emitted normalized/minified
  under `requestBody.content."application/json".schema`; malformed text is a typed
  `error.InvalidRequestSchema`, not a panic or silent drop.
- **Concurrency:** reentrant — the generator is a pure function of an immutable (post-`build`)
  `Router`; `Endpoint` regenerates the document per request with no shared mutable state, safe to
  call concurrently from multiple request-handling threads.
- **No external assets:** Swagger-UI needs CDN JS/CSS (a CSP and provenance problem), so it is
  deliberately not served. The optional `docs_path` instead serves a tiny self-contained HTML viewer
  (inline CSS + vanilla JS, zero external requests) that fetches the spec and lists operations.

**Threat model / out of scope** — Not a security boundary: the generated document exposes exactly
the route/method/doc metadata already registered in the `Router` — anything sensitive in a
`summary`/`description`/`request_schema` string is echoed verbatim into a public-by-default
`/openapi.json`, so callers must not put secrets in `RouteDoc` fields. `Endpoint` does not add its
own auth — gate `/openapi.json` (and the optional docs page) behind the router's own auth middleware
if it should not be public. It does not validate that `request_schema`/`responses` describe the
handler's *actual* behavior — it only validates that `request_schema` is well-formed JSON Schema
text; a documented contract the handler doesn't honor is a caller bug this module cannot catch. It
does not generate client SDKs, do request/response validation at runtime, or support anything beyond
3.1.0 document generation (no OpenAPI 3.0/Swagger 2.0 output).

**Verification** — `zig build test-openapi`, 7 tests. Offline: golden OpenAPI 3.1 JSON for a known
route set (`:id`→`{id}` conversion, path parameters present and required, `RouteDoc` fields
surfaced, default 200 for undocumented routes); empty router produces a valid empty-`paths`
document with no panic; method grouping is deterministic by `http.Method` enum order rather than
registration order; malformed `request_schema` returns `error.InvalidRequestSchema`; the endpoint
serves the spec on GET/HEAD, returns 405 with `Allow` on other methods, and passes through
everything else, driven socket-free via `http.Server.serveStream`; the self-contained docs page is
checked for zero external asset references. In-process integration: a real `http.Server` + router +
endpoint bound to `127.0.0.1:0`, fetched with `http.Client` — the served document parses and
contains the registered routes/operations.

**Status** — `gap · any · util · reentrant` · deps: `router`, `http` (+ `std.json`).

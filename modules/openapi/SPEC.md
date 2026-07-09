# openapi — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Two layers. `Generator` walks `Router.routes()` and emits a valid OpenAPI 3.1 JSON document
(`openapi: "3.1.0"`, `info` from `Info`, `paths` with router patterns converted to templates —
`:id` → `{id}`, `*rest` → `{rest}` — methods grouped per path). `Endpoint` is an intercepting
`router.Middleware` (the `metrics.Endpoint` pattern, needed because `router.Handler` is a stateless
fn pointer and cannot close over state) serving the generated document on `GET /openapi.json`; must
be registered before the routes it documents (chi's rule) but generates the spec fresh per
request, so it still sees routes registered after it. Deterministic, minified output: paths in
first-registration order, methods per path in `http.Method` declaration order, fixed key order
inside every object, no whitespace — two runs over the same router produce byte-identical
documents. Documented FastAPI-shape compromises: path parameters always `required: true` with
`schema: {type: "string"}`; a `*wildcard` segment becomes a plain `{param}` (OpenAPI has no
cross-segment template, matching FastAPI's own `:path` compromise); undocumented routes get a
minimal 200-only operation; `operationId` deliberately omitted (fn-pointer routes have no stable
name to derive one from); implicit HEAD→GET auto-route and 404/405 fallbacks are not emitted (they
are dispatch behavior, not operations). `RouteDoc.request_schema` (JSON Schema as text) is parsed
and re-emitted normalized/minified; malformed text is a typed `error.InvalidRequestSchema`, never a
panic or silent drop. Concurrency: reentrant — the generator is a pure function of an immutable
(post-`build`) `Router`; `Endpoint` regenerates per request with no shared mutable state. No
external assets: Swagger-UI needs CDN JS/CSS (a CSP/provenance problem) so it is deliberately not
served; the optional `docs_path` instead serves a tiny self-contained HTML viewer (inline CSS +
vanilla JS, zero external requests). Clean-room; design references only (behavior, no source
copied — see NOTICE): FastAPI (document shape) and utoipa (route-metadata→spec mapping); format per
the OpenAPI Specification 3.1.0.

## Threat model / out of scope
Not a security boundary: the generated document exposes exactly the route/method/doc metadata
already registered in the `Router` — anything sensitive in a `summary`/`description`/
`request_schema` string is echoed verbatim into a public-by-default `/openapi.json`, so callers
must not put secrets in `RouteDoc` fields. `Endpoint` adds no auth of its own — gate
`/openapi.json` (and the docs page) behind the router's own auth middleware if it should not be
public. Does not validate that `request_schema`/`responses` describe the handler's actual behavior
— only that `request_schema` is well-formed JSON Schema text; a documented contract the handler
doesn't honor is a caller bug this module cannot catch. Does not generate client SDKs, do
request/response validation at runtime, or support OpenAPI 3.0/Swagger 2.0 output.

## Verification
`zig build test-openapi`, 7 tests. Offline: golden OpenAPI 3.1 JSON for a known route set
(`:id`→`{id}` conversion, required path parameters, `RouteDoc` fields surfaced, default 200 for
undocumented routes); empty router produces a valid empty-`paths` document with no panic; method
grouping deterministic by `http.Method` enum order; malformed `request_schema` returns
`error.InvalidRequestSchema`; the endpoint serves GET/HEAD, 405+`Allow` on other methods, passes
through everything else (driven socket-free via `http.Server.serveStream`); the docs page is
checked for zero external asset references. In-process integration: a real `http.Server` + router +
endpoint bound to `127.0.0.1:0`, fetched with `http.Client` — the served document parses and
contains the registered routes/operations.

## Backlog / deferred
OpenAPI 3.0/Swagger 2.0 output, request/response runtime validation, and client SDK generation are
explicitly out of scope, not planned. Richer path-parameter typing beyond `string` would require
`router` itself to carry richer capture types.

## Status
`gap · any · util · reentrant` + deps: `router`, `http` (+ `std.json`) — canonical source is
`pub const meta` in src/root.zig.

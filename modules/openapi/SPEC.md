# openapi — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Two layers. `Generator` walks `Router.routes()` and emits a valid OpenAPI 3.1 JSON document
(`openapi: "3.1.0"`, `info` from `Info`, `paths` with router patterns converted to templates —
`:id` → `{id}`, `*rest` → `{rest}` — methods grouped per path). `Endpoint` is an intercepting
`router.Middleware` (the `metrics.Endpoint` pattern, needed because `router.Handler` is a stateless
fn pointer and cannot close over state) serving the generated document on `GET /openapi.json`; must
be registered before the routes it documents (chi's rule) — the document is built once, lazily, on
the first request that needs it, and cached (behind a lock) for the Endpoint's whole lifetime, so a
route registered AFTER that first request will not appear. Deterministic, minified output: paths in
first-registration order, methods per path in `http.Method` declaration order, fixed key order
inside every object, no whitespace — two runs over the same router produce byte-identical
documents. Documented FastAPI-shape compromises: path parameters always `required: true` with
`schema: {type: "string"}`; a `*wildcard` segment becomes a plain `{param}` (OpenAPI has no
cross-segment template, matching FastAPI's own `:path` compromise); undocumented routes get a
minimal 200-only operation; implicit HEAD→GET auto-route and 404/405 fallbacks are not emitted (they
are dispatch behavior, not operations). `RouteDoc.request_schema` (JSON Schema as text) is parsed
and re-emitted normalized/minified; malformed text is a typed `error.InvalidRequestSchema`, never a
panic or silent drop.

**`operationId` (audit finding openapi-F13, reversing a prior "deliberately omitted" decision):**
now always emitted, deterministically — lowercase method + `_` + the converted path's segments
joined by `_`, a templated segment's `{`/`}` stripped (`GET /users/{id}` → `get_users_id`). Unique
across one document BY CONSTRUCTION: `operationId` is textually `(method, converted_path)`, and
`error.PathCollision` (below) already guarantees that pair cannot repeat. Independently confirmed
against OAS 3.1 §4.8.10's uniqueness requirement with `openapi_spec_validator` (see the "external
anchor" test file section) — a document with two operations sharing one `operationId` is REJECTED
by the real validator, the exact failure mode this construction rules out.

**UTF-8 (audit finding openapi-F4):** every `[]const u8` this module is about to hand to
`std.json.Stringify` — `Info` fields, every `RouteDoc` string field, and each route's raw pattern
(which also covers the converted path: `convertPattern` only rewrites `:`/`*`/`{`/`}`, all ASCII) —
is checked with `std.unicode.utf8ValidateSlice` BEFORE any output is written, atomically failing
the whole build with `error.InvalidUtf8` rather than emitting a partial document. JSON text MUST be
valid UTF-8 (RFC 8259 §8.1); `std.json.Stringify.write([]const u8)` does not enforce that itself —
a non-UTF-8 slice silently becomes a JSON array of byte values instead of a string, and a raw
non-UTF-8 byte reaching an `objectField` key goes out unescaped, producing text `std.json` itself
refuses to re-parse (falsifying a prior PASS-log claim that "route metadata cannot break the
document structure").

**Path collisions are a build error, not a silent merge (audit finding openapi-F5):** two different
`router` routes can convert to the same `(path, method)` — `/f/:p` and `/f/*p` both become
`/f/{p}`, or a literal `/f/{p}` collides with `/f/:p` — and `router` accepts both as distinct,
independently dispatchable routes. Silently keeping only the first (as before) made a real,
reachable route disappear from the document without a trace; that is `error.PathCollision` now.
This is a different situation from a genuinely duplicate key with only ONE underlying value (two
`RouteDoc.Response`s sharing a status code, or a pattern reusing one capture name — both still
"first wins", correct because there is nothing else to pick).

**Self-check (audit finding openapi-F9, closes F12 as a strict subset):** `Generator.build` parses
its own generated JSON back and runs `validateOpenApi31` (below) on it before returning — the
checker already existed and already caught this class of defect in the module's OWN tests (an
empty `info.title`, an F4-class encoding problem turning a string into an array), but never ran on
a document before it reached a caller. Costs one extra parse of the whole document, paid once per
`Endpoint`'s lifetime (the F1 fix already caches the outcome after the first call).

**Excluding a route (audit finding openapi-F11, additive):** `Info.include: ?*const fn (router.Route)
bool`, `null` by default (every registered route is documented, the pre-fix behavior). Applied
before anything else touches a route, so an excluded route's metadata is never UTF-8-checked or
written and cannot trigger `error.InvalidUtf8`/`error.PathCollision` against one that IS included.

Concurrency: `Generator.build`/`Generator.write` are reentrant — pure
functions of an immutable (post-`build`) `Router` — but `Endpoint` is `.threadsafe`, not
`.reentrant`: it builds the document once behind a lock (a failed build is cached too, so a bad
`request_schema` does not pay full generation cost on every request either) and serves the same
cached bytes for its whole lifetime; a route registered after the first request is invisible to
it. ⚠ **Precondition, not a guarantee (audit finding openapi-F10):** "post-`build`" above means
registration (`add`/`addDoc`/`group`) has FULLY completed before the Router is handed to
`http.Server`/any concurrent dispatch — `r.routes()` is read once, unsynchronized, by whichever
request thread happens to trigger the build, so a route registered concurrently with (not just
chronologically before) that read races `Router`'s own backing slice. The audit could not force a
crash (`Router` allocates from an arena, so a grown-past block stays mapped), but did not need to:
the fix is the same "building is single-owner" phase discipline `router/SPEC.md` §Concurrency
already requires, made explicit here and in `Endpoint`'s own doc comment, not new synchronization. Responses carry a strong `ETag` (a fingerprint of the cached document); a matching
`If-None-Match` gets `304`. No external assets: Swagger-UI needs CDN JS/CSS (a CSP/provenance problem) so it is deliberately not
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
`zig build test-openapi`. Offline: golden OpenAPI 3.1 JSON for a known route set
(`:id`→`{id}` conversion, required path parameters, `RouteDoc` fields surfaced, default 200 for
undocumented routes); empty router produces a valid empty-`paths` document with no panic; method
grouping deterministic by `http.Method` enum order; malformed `request_schema` returns
`error.InvalidRequestSchema`; the endpoint serves GET/HEAD, 405+`Allow` on other methods, passes
through everything else (driven socket-free via `http.Server.serveStream`); the docs page is
checked for zero external asset references. In-process integration: a real `http.Server` + router +
endpoint bound to `127.0.0.1:0`, fetched with `http.Client` — the served document parses and
contains the registered routes/operations.

### External-anchor investigation: `openapi_spec_validator` (2026-08-01, done)

The in-house structural checker (`validateOpenApi31`) and the adopted OAI example (both above)
prove this module accepts a real document and that its own rules fire — not that a real,
schema-driven validator agrees. `openapi_spec_validator` (JSON-Schema-backed, the reference
OAS validator) was run once, offline, in a throwaway venv (`~/.cache/zig-libs-openapi`),
against two documents: (1) the exact JSON `Generator.build` produces for the route set in
"generate: golden OpenAPI 3.1 document for a known route set" — `validate()` raised no
exception, confirming this module's own generated output is genuinely valid OAS 3.1, not
merely self-consistent; (2) a deliberately invalid document missing a response
`description` — rejected with `OpenAPIValidationError: 'description' is a required
property`, the same structural defect this module's own checker already reports as
`error.MissingResponseDescription`, now independently confirmed rather than assumed. **No
disagreement was found.** Both documents and the real verdict are frozen as permanent
offline tests in `src/root.zig` (`external anchor: …`); per the governing rule the tool was
run once and is not re-invoked at test time. No `/NOTICE` entry (black-box validating
oracle, root NOTICE §0); the module's existing NOTICE for the adopted OAI example document
is unrelated and unaffected.

## Backlog / deferred
OpenAPI 3.0/Swagger 2.0 output, request/response runtime validation, and client SDK generation are
explicitly out of scope, not planned. Richer path-parameter typing beyond `string` would require
`router` itself to carry richer capture types.

## Status
`gap · any · util · threadsafe` + deps: `router`, `http` (+ `std.json`) — canonical source is
`pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/root.zig:749+ freezes openapi_spec_validator's verdict on this module's OWN generated document (accepted) and on a deliberately invalid one (rejected, for the same reason validateOpenApi31 reports) -- teeth in both directions; :595 adds the OAI's published v3.1 example. The generator's route-to-path mapping beyond that document is self-graded

**How it got there.** The anchoring work landed. DONE 0bbcefe: real validator both directions; found in-house checker blind to path-param rule

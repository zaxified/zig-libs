# openapi

OpenAPI 3.1 document generation from a `router` route table, plus a
ready-made `GET /openapi.json` endpoint middleware. "Self-documentation":
the spec is derived from the live `Router.routes()` table and per-route
`RouteDoc` metadata (`Router.addDoc`), so the docs cannot drift from the
code. Closes the Web service / API cluster.

- **Status:** `gap` — nothing comparable in Zig std or the ecosystem.
- **Model after:** FastAPI's auto-generated spec (the emitted document
  shape — operation key order, path-parameter objects, the default
  `"Successful Response"` 200) and utoipa (Rust; route-metadata→spec
  mapping). Document format per the OpenAPI Specification 3.1.0.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant — the
  generator is a pure function of an immutable (post-build) Router; the
  endpoint generates per request with no shared mutable state.
- **Deps:** `router`, `http` (+ `std.json`).

Provenance: clean-room. Design references: FastAPI (MIT; generated-spec
shape + defaults), utoipa (MIT OR Apache-2.0), OpenAPI Specification 3.1.0
(Apache-2.0, OpenAPI Initiative). No third-party source copied. See
`NOTICE`.

## Usage

```zig
const router = @import("router");
const openapi = @import("openapi");

var r = router.Router.init(gpa);
defer r.deinit();

var docs: openapi.Endpoint = .{
    .gpa = gpa,
    .router = &r,
    .info = .{ .title = "My API", .version = "1.0.0" },
    // .docs_path = "/docs",           // optional self-contained HTML viewer
};
try r.use(docs.middleware());          // middleware BEFORE routes (chi rule);
                                       // the spec is generated per request, so
                                       // it sees everything registered below
try r.get("/health", health);          // undocumented → minimal operation
try r.addDoc(.post, "/users", createUser, .{
    .summary = "Create a user",
    .tags = &.{"users"},
    .request_schema = "{\"type\":\"object\",\"required\":[\"name\"]}",
    .responses = &.{.{ .status = 201, .description = "Created" }},
});
// GET /openapi.json now serves the OpenAPI 3.1 document.

// Or generate without serving (CI artifact, file on disk, ...):
const json = try openapi.Generator.build(gpa, &r, .{ .title = "My API", .version = "1.0.0" });
defer gpa.free(json);
```

## Emitted document (documented choices)

| Topic | Behavior |
|---|---|
| Version | `openapi: "3.1.0"`; `info` from `Info` (title + version required, description optional) |
| Paths | router patterns → templates: `:id` → `{id}`, `*rest` → `{rest}`; methods grouped per path |
| Determinism | paths in first-registration order; methods per path in `http.Method` declaration order; fixed key order; minified |
| Path params | always `required: true`, `schema: {type: "string"}` (router captures raw path bytes); a `*wildcard` becomes a plain `{param}` (OpenAPI has no cross-segment template — FastAPI's `:path` compromise) |
| `RouteDoc` | surfaces `summary`/`description`/`tags`/`requestBody`/`responses`/`deprecated`; `request_schema` is JSON-validated and re-emitted normalized under `requestBody.content."application/json".schema` (malformed → `error.InvalidRequestSchema`) |
| Undocumented routes | minimal operation with default `responses: {"200": {"description": "Successful Response"}}` (FastAPI's default) |
| Not emitted | the implicit HEAD→GET auto-route, 404/405 fallbacks, `operationId` (optional; no stable naming source in a fn-pointer table) |

**Endpoint** is an *intercepting* `router.Middleware` (the
`metrics.Endpoint` pattern — `router.Handler` is a stateless fn pointer and
cannot close over state): `GET`/`HEAD` on `path` answers the document, other
methods get 405 + `Allow`, everything else passes through.

**Docs page choice:** Swagger-UI needs external JS/CSS (CDN or bundling —
a CSP and provenance problem), so it is deliberately **not** served.
Instead, the optional `docs_path` serves a tiny self-contained HTML viewer
(inline CSS + vanilla JS, zero external assets) that fetches the spec and
lists every operation with method, path, tags, summary and deprecation.

## Follow-up unlocked

`router.Ctx.matchedPattern()` (added together with this module) gives
`metrics` a bounded-cardinality **route-pattern label** for its request
counter/histogram — the label that was deliberately absent because labeling
by raw path would be the cardinality footgun. Not wired up in this task.

## Verification

- Offline: golden OpenAPI 3.1 JSON for a known route set (`:id`→`{id}`,
  path parameters present + required, doc fields surfaced, default 200 for
  undocumented, deterministic method order); empty router → valid
  empty-`paths` document; malformed `request_schema` → error; endpoint +
  docs page driven through the socket-free `http.Server.serveStream`.
- In-process integration: `http.Server` + router + endpoint on
  `127.0.0.1:0`, fetched with `http.Client` — the served document parses
  and contains the registered routes/operations.

`zig build test-openapi`

# SPEC — router route-enumeration + `openapi` (T5.11)

Two coupled pieces, ONE task: (Step 1) a small `router` enhancement to expose the registered route
table + the matched pattern, then (Step 2) the `openapi` module that generates an OpenAPI 3.1 spec
from it. Closes the Web/API cluster. Model after: FastAPI auto-docs / utoipa (Rust) / swaggo.
Deps (openapi): `router`, `http` (uses `std.json`). New entry
`.{ .name = "openapi", .deps = &.{ "router", "http" } }`.

## Why

"Self-documentation" — the API describes itself so docs can't drift from code. Also unblocks the
deferred `metrics` route-pattern label (a future follow-up — do NOT touch `metrics` in this task).

## Step 1 — router enhancement (edit `modules/router/src/root.zig`)

Add, without breaking the existing public API or any existing test:
1. **`Router.routes()`** — enumerate registered routes as `{ method, pattern, doc: ?RouteDoc }`
   (iterator or an owned slice; document allocation/ownership). Deterministic order.
2. **`Ctx.matchedPattern() ?[]const u8`** — the route pattern that matched this request (stashed in
   `Ctx` during dispatch; null for 404). This is the thing `metrics`/`openapi` need.
3. **Optional per-route doc metadata:** a registration variant, e.g. `addDoc(method, pattern, handler,
   RouteDoc)` (or an overload), where `RouteDoc { summary, description, tags, request_schema,
   responses, deprecated }` is all-optional. Existing `add`/`get`/`post` keep working (doc = null).
   Keep `RouteDoc` a plain data struct the router just stores + returns.
Add router tests for `routes()` enumeration + `matchedPattern()` on hit/miss. Router's own test
count must stay green.

## Step 2 — `openapi` module

1. **Spec generation:** `Generator.build(router, Info) → std.json.Value` (or write directly) producing
   a valid **OpenAPI 3.1** document: `openapi: "3.1.0"`, `info` (title/version/description from `Info`),
   `paths` — convert `:param`→`{param}` and `*wild`→`{wild}`, group methods under each path, each
   operation carries `parameters` (path params, `required:true`), and — when the route has a
   `RouteDoc` — `summary`/`description`/`tags`/`requestBody`/`responses`/`deprecated`. Routes without a
   doc get a minimal operation with a default `responses: { "200": {description} }`. Valid JSON,
   deterministic key/order where feasible.
2. **Serve:** an `Endpoint`-style intercepting middleware (same pattern as `metrics` — `router.Handler`
   can't close over state) serving **`GET /openapi.json`** with `application/json`. Optionally a tiny
   docs HTML page — but Swagger-UI needs external JS/CSS (CSP/bundling problem), so either skip it or
   serve a minimal self-contained HTML that fetches the spec; **do NOT** pull external assets. Note
   the choice.

## Acceptance / verification

- **Offline unit tests:** `router.routes()` returns the registered set (methods + patterns, doc
  attached); `matchedPattern()` correct on hit + null on miss; openapi generation → a **golden**
  OpenAPI 3.1 JSON for a known route set (assert `openapi`/`info`/`paths`, `:id`→`{id}` conversion,
  path `parameters` present+required, doc fields surfaced, default 200 for undocumented); malformed/
  empty router → a valid empty-`paths` doc, no panic.
- **In-process integration (must NOT skip normally):** router (a few routes, some with `addDoc`) +
  `http.Server` + `http.Client` + the openapi endpoint → `GET /openapi.json` returns 200 with a JSON
  body that parses and contains the routes/operations.
- `zig build test-openapi`, `zig build test-router`, and `zig build test` (all) green, Debug +
  ReleaseFast; `zig fmt --check` clean. openapi registered with `deps = &.{"router","http"}`.

## Notes for the implementer

- Use the **zig skill** (std.json Value building/stringify, std.Io.Writer). Reuse `router`'s types +
  `http.Server` ResponseWriter. Emit strict, valid OpenAPI 3.1 (validate the shape in tests).
- Keep Step 1 minimal and backward-compatible — many modules depend on `router`; do not break them
  (run `zig build test` after the router edit before starting openapi).
- SPDX header + a `Provenance:` line on the new module (clean-room; design refs FastAPI MIT / utoipa
  MIT-or-Apache / OpenAPI 3.1 spec). Update `NOTICE` with the design ref. Do NOT edit PLAN.md.
- Follow-up (NOT this task, just note it in the openapi README): `metrics` can now use
  `Ctx.matchedPattern()` for its route-pattern label.

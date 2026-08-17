# cors

Cross-Origin Resource Sharing as a global `router` middleware: preflight
(`OPTIONS` + `Access-Control-Request-Method`) interception with a bodyless
204, and `Access-Control-*` header injection on actual cross-origin
requests. T5.7 of the Web/API cluster.

Provenance: original work of the zig-libs authors (MIT) — no third-party code. Design
references: rs/cors (Go, MIT — the primary behavioral model: preflight
always intercepted, origin/method/header gates, failed preflight = 204
without CORS headers) and expressjs/cors (MIT — the reflect-request-headers
default). Protocol semantics from the WHATWG Fetch standard (CORS protocol)
and RFC 9110. No source copied.

- **Model after:** rs/cors (Go) + expressjs/cors.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant — an
  initialized `Cors` is immutable; no clock, no locks, no hidden globals;
  the only allocation is the init-time join of the configured lists
  (`deinit` frees it). Hot path reflects borrowed request slices only.
- **Deps:** `router` (Middleware/Ctx/Next), `http` (`Request.header`,
  `ResponseWriter` setStatus/setHeader/end).

## Usage

```zig
const cors = @import("cors");
const router = @import("router");

var c = try cors.Cors.init(gpa, .{
    .allowed_origins = .{ .list = &.{ "https://app.example", "http://localhost:5173" } },
    .allowed_methods = &.{ .get, .post, .delete },
    // .allowed_headers = .reflect (default) — or .{ .list = &.{ "Content-Type", "Authorization" } }
    .exposed_headers = &.{"X-Request-Id"},
    .allow_credentials = true,
    .max_age_s = 600,
});
defer c.deinit();

var r = router.Router.init(gpa);
defer r.deinit();
try r.use(c.middleware()); // GLOBAL, before routes (chi rule)
try r.get("/api/thing", handler);
```

Register it **globally** (`router.use`, before any route): the global chain
also wraps the router's 404/405 fallbacks, so a preflight to a GET-only
route is intercepted *before* it would 405 (the router does not synthesize
`OPTIONS` routes), and a preflight to an unknown path is answered instead
of 404ing. The `Cors` must outlive the router serving requests, at a
stable address (the middleware's `state` points at it).

## Default posture (explicit opt-in)

`allowed_origins` defaults to **`.none`** — the middleware emits no CORS
headers at all until origins are explicitly configured. This deviates from
rs/cors (which defaults to the permissive `*`) on purpose: CORS is an
explicit grant of cross-origin readability, and a permissive default hands
it out silently. Other defaults:

| Option | Default | Header |
|---|---|---|
| `allowed_origins` | `.none` (opt-in; `.any`, `.list`, `.predicate`) | `Access-Control-Allow-Origin` |
| `allowed_methods` | `GET, HEAD, POST` (the CORS-safelisted set; rs/cors default) | `Access-Control-Allow-Methods` |
| `allowed_headers` | `.reflect` (echo `Access-Control-Request-Headers`) | `Access-Control-Allow-Headers` |
| `exposed_headers` | none | `Access-Control-Expose-Headers` |
| `allow_credentials` | `false` | `Access-Control-Allow-Credentials` |
| `max_age_s` | `null` = omit (`0` = disable preflight caching) | `Access-Control-Max-Age` |

`allowed_headers = .reflect` matches expressjs/cors (rs/cors ships a fixed
small list instead — a classic "Authorization not allowed" gotcha). Header
*names* are not sensitive and the origin gate remains the security
boundary, so reflecting maximizes compatibility. Use `.list` to be strict;
matching is then case-insensitive and a preflight requesting anything
outside the list fails.

## Credentials vs the `*` wildcard (rejected at init)

The Fetch standard forbids `Access-Control-Allow-Origin: *` on responses
to credentialed requests, and the common workaround — reflecting *any*
origin while sending `Access-Control-Allow-Credentials: true` — grants
every website on the internet credentialed access to your API.
`Cors.init` therefore **rejects** `allowed_origins = .any` combined with
`allow_credentials = true` with `error.CredentialsWithWildcardOrigin`
instead of silently downgrading. If you genuinely need reflect-any with
credentials, write a `.predicate` that returns true — an explicit,
greppable opt-in to the footgun.

## Unconditional wildcard CORS (`allow_unconditional_wildcard`, opt-in deviation)

Everything above is spec-correct CORS and stays the default: no `Origin`
header means no CORS headers, and a plain `OPTIONS` (no
`Access-Control-Request-Method`) is not a preflight — it routes normally.
That is the wrong shape for exactly one migration case: an existing API
that has always answered *every* `OPTIONS` with 204 and put
`Access-Control-Allow-Origin: *` on *every* response, and cannot change what
is on the wire to adopt this module.

```zig
var c = try cors.Cors.init(gpa, .{
    .allowed_origins = .any,               // required — see below
    .allow_unconditional_wildcard = true,  // the deviation, spelled out
});
```

The field name says what it costs: turning it on means leaving spec-correct
CORS behind, not just enabling a feature. It requires `allowed_origins =
.any` — any other value fails `Cors.init` with
`error.UnconditionalWildcardRequiresAnyOrigin`, since the option's whole
meaning is "wildcard on every response" and nothing else is coherent to
gate on. Once set:

- every actual (non-preflight) response gets `Access-Control-Allow-Origin: *`,
  `Origin` present or not, method allowed or not;
- every `OPTIONS` request — not just a true preflight — is intercepted and
  answered `204` with the same wildcard header.

Both behaviours live behind the one field rather than two, on purpose: they
are two symptoms of the same legacy posture (a CORS gate that never
conditioned on `Origin`), and enabling only one half would still change the
wire shape for the other kind of request — the exact problem the option
exists to avoid. See SPEC.md "Unconditional wildcard CORS" for the full
reasoning.

## Semantics (rs/cors)

- **Preflight** = `OPTIONS` **with** `Access-Control-Request-Method`
  (plain `OPTIONS` routes normally). Always intercepted: 204, no body, no
  handler runs — whether or not the origin is allowed and whether or not a
  route exists. The CORS headers appear only when origin + requested
  method + requested headers all pass; a failed preflight is a 204 without
  them (that is how the browser learns "no"). Every intercepted preflight
  carries `Vary: Origin, Access-Control-Request-Method,
  Access-Control-Request-Headers`.
- **Actual requests** always continue down the chain — CORS never blocks
  server-side handling, it only withholds the headers that let a
  cross-origin script *read* the response. Headers are set when the
  `Origin` is present + allowed **and** the request method is in
  `allowed_methods` (rs/cors gate; `OPTIONS` always passes). `.any` emits
  the literal `*`; a list/predicate match echoes the specific origin and
  adds `Vary: Origin`. Absent or disallowed `Origin` → nothing is set.
- **Origin matching is an exact byte compare** (list) or your predicate.
  Configure the canonical serialization browsers send: lowercase scheme +
  host, no trailing slash, port only when non-default
  (`https://app.example`, `http://localhost:5173`). `HTTPS://APP.EXAMPLE`
  will not match — deliberate, per this module's spec.

Known limitations: a handler that sets `Vary` itself **replaces** the
middleware's `Vary: Origin` (`http`'s `setHeader` replaces by name and has no
append-or-read counterpart, so `cors` cannot merge). The response still carries
a per-origin `Access-Control-Allow-Origin`, so a shared cache keyed on the
surviving `Vary` list can serve one origin's response to another — **a handler
that sets `Vary` on a CORS route must include `Origin` in its own list**
(`Vary: Accept-Encoding, Origin`). Both shapes are pinned by a test; rs/cors's
`OptionsPassthrough` (let intercepted preflights fall through to your own
`OPTIONS` routes) and `Access-Control-Allow-Private-Network` are out of
scope for now.

## Header timing vs. `ResponseWriter.reset()`

`cors` sets its actual-request headers **before** `next.run` — i.e. before
your handler (and any inner middleware) runs. If an *outer* middleware
does response-rewriting work **after** `next.run` — e.g. to replace a
`text/plain` denial body with JSON — and calls `ResponseWriter.reset()` to
do it, `reset()` clears the whole header list, `cors`'s included. Nothing
puts them back automatically: `cors` cannot see the reset happen, and
`http.Server.ResponseWriter` has no snapshot/restore.

**The rule:** if your outer middleware calls `reset()` after `next.run`,
call `your_cors.applyActual(ctx.req, ctx.res)` again immediately
afterward, before writing the new body:

```zig
fn rewriteDenials(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    try next.run(ctx);
    if (yourDenialCondition(ctx)) { // e.g. the handler set a plain-text 403
        try ctx.res.reset();
        try my_cors.applyActual(ctx.req, ctx.res); // re-apply — reset() wiped it
        ctx.res.setStatus(403);
        try ctx.res.setHeader("Content-Type", "application/json");
        try ctx.res.writeAll("{\"error\":\"forbidden\"}");
    }
}
```

`applyActual` re-runs the exact same origin/method gate `cors` used the
first time — it is idempotent, safe to call twice, and stays correct if
`cors`'s gate logic ever changes (your middleware does not reimplement it).
This does not apply to preflights: a preflight never calls `next.run` at
all (`cors` short-circuits it), so there is no downstream middleware to
wrap it and nothing to reapply. See SPEC.md "Header timing vs.
`ResponseWriter.reset()`" for why the ordering itself was not changed
instead.

## Verification

`zig build test-cors` — offline goldens over the socket-free
`http.Server.serveStream` (byte-exact 204 preflight with the full header
set + handler-not-invoked proof; `.reflect` echo + absent-ACRH omission;
each failing gate → 204 with `Vary` and zero CORS headers, including the
byte-compare case-sensitivity check; preflight interception on would-be
405 and 404 paths; plain `OPTIONS` routing normally with actual-request
headers; actual-request echo + `Vary: Origin` + credentials + exposed
headers; `.any` → `*` without `Vary`; disallowed/absent Origin and `.none`
passthrough with the handler still running; the actual-request method
gate; predicate origins on both request shapes; `*`+credentials init
rejection; `allow_unconditional_wildcard` requires `.any` at init and, once
set, emits the wildcard on an Origin-absent request and intercepts a bare
`OPTIONS` with 204 (both sit beside the unchanged default in the same
test); `max_age_s` 0/max formatting and the join precomputations),
plus an in-process integration run (`router` + `http.Server` +
`http.Client` over loopback: preflight `OPTIONS` → 204 + CORS headers with
the handler never invoked; `GET` with an allowed `Origin` →
`Access-Control-Allow-Origin` + `Vary`; a disallowed origin → no CORS
headers) that only skips when loopback binding is unavailable.

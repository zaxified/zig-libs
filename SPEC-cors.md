# SPEC — `cors`

Cross-Origin Resource Sharing as a `router` middleware. Web/API cluster (T5.7).
`gap · any · util · reent`. Model after: `rs/cors` (Go) + `expressjs/cors`. Deps: `router`, `http`.
New `build.zig` entry `.{ .name = "cors", .deps = &.{ "router", "http" } }`.

## Why

Browser clients on another origin need CORS headers + preflight handling. A small, mostly-stateless
middleware. (Router doesn't synthesize `OPTIONS`, and a preflight to a GET-only route would 405 —
but global middleware runs on 404/405 too, so a global cors middleware can short-circuit the
preflight before that.)

## Scope

1. **Preflight (`OPTIONS` + `Access-Control-Request-Method` header):** short-circuit with **204**
   (no body) + the CORS headers below; do NOT call `next`.
2. **Actual requests:** if the `Origin` is allowed, set `Access-Control-Allow-Origin` (echo the
   specific origin, or `*` when configured and credentials are off), `Vary: Origin` (when reflecting),
   `Access-Control-Allow-Credentials` (if enabled), `Access-Control-Expose-Headers`; then `next`.
   If `Origin` is absent or not allowed → set nothing, just `next` (a non-CORS request).
3. **Config:** `allowed_origins` (exact list, `*`, or a predicate fn), `allowed_methods`,
   `allowed_headers` (or reflect `Access-Control-Request-Headers`), `exposed_headers`,
   `allow_credentials: bool`, `max_age_s` (preflight cache). **Secure defaults:** do NOT combine
   `*` origin with credentials (spec-forbidden — reject that config or drop credentials; document).
   Default allowed methods = the safe set; default origins = none (caller must opt in) OR `*` — pick
   one and document (rs/cors defaults to permissive-ish; prefer explicit).

## Public API sketch (final shape your call)

```zig
pub const Cors = struct {
    pub fn init(gpa, Options) Cors;
    pub fn deinit(*Cors) void;
    pub fn middleware(self) router.Middleware;   // preflight short-circuit + header injection
};
```

## Acceptance / verification

- **Offline unit tests:** preflight → 204 with `Access-Control-Allow-Methods/-Headers/-Max-Age` and
  the right `Allow-Origin`; actual request with an allowed `Origin` → `Access-Control-Allow-Origin`
  (+ `Vary: Origin`, credentials header when enabled); disallowed origin → no CORS headers; absent
  Origin → passthrough; `*`+credentials config handled safely (rejected or downgraded, tested);
  reflect-request-headers path.
- **In-process integration (must NOT skip normally):** router+`http.Server`+`http.Client` — a
  preflight `OPTIONS` gets 204 + headers (handler not invoked); a `GET` with `Origin` gets the
  `Access-Control-Allow-Origin`; a disallowed origin gets none.
- `zig build test-cors` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check` clean.

## Notes for the implementer

- Use the **zig skill**. Register as a GLOBAL `router` middleware (via `use`) so it sees preflights
  before 405. Reuse `router.Middleware {state,run}`, `Ctx`, `ctx.res` (setStatus/setHeader/end);
  for the preflight short-circuit, set status 204 + headers + `end()` and do NOT call `next`.
- Origin matching is a byte compare against the configured list (or predicate); no allocation on the
  hot path beyond what header reflection needs.
- Document the credentials-vs-wildcard rule and the chosen default posture.
- SPDX header + a `Provenance:` line (clean-room; design refs rs/cors MIT / expressjs cors MIT).

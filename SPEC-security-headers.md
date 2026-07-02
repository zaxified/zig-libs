# SPEC — `security-headers`

Secure-by-default HTTP security response headers as a `router` middleware. Web/API cluster (T5.6).
`gap · any · util · reent`. Model after: helmet.js defaults + OWASP Secure Headers Project. Deps:
`router`, `http`. New `build.zig` entry `.{ .name = "security-headers", .deps = &.{ "router", "http" } }`.
(Module dir `modules/security-headers/`; the importable name may be `security_headers` — pick the
form `@import` accepts and register that exact string in `build.zig`; note it in the README.)

## Why

A directly-internet-facing API should ship the standard hardening headers by default. This is a
tiny, stateless middleware that sets them, configurable per header.

## Scope

Set these response headers (secure defaults; each individually overridable/disable-able):

- **`Strict-Transport-Security`** (HSTS): `max-age` (default ~1 year), `includeSubDomains`, optional
  `preload`. Note in docs: only meaningful over HTTPS (harmless over plain HTTP; gate/config it).
- **`Content-Security-Policy`**: caller-supplied policy string (no universally-safe default — default
  to a restrictive `default-src 'self'` **or** off-by-default with a clear doc; pick one, document).
  Optional `Content-Security-Policy-Report-Only`.
- **`X-Content-Type-Options: nosniff`** (default on).
- **`X-Frame-Options: DENY`** (default) — plus note CSP `frame-ancestors` is the modern form.
- **`Referrer-Policy`** (default `no-referrer` or `strict-origin-when-cross-origin` — pick, document).
- **`Permissions-Policy`** (caller-supplied; default minimal/empty).
- **Cross-Origin isolation:** `Cross-Origin-Opener-Policy` (default `same-origin`),
  `Cross-Origin-Resource-Policy` (default `same-origin`), `Cross-Origin-Embedder-Policy` (default
  **off** — it breaks embeds; opt-in).
- Remove/replace **`Server`** header value if configured (fingerprint reduction) — optional.

## Public API sketch (final shape your call)

```zig
pub const SecurityHeaders = struct {
    pub fn init(Options) SecurityHeaders;   // one bool/optional per header + string values
    pub fn middleware(self) router.Middleware;   // sets headers, then next
    // secure defaults constructor: SecurityHeaders.strict(.{}) or default init()
};
```

Middleware sets the configured headers on the `ResponseWriter` **before** calling `next` (so the
handler's head is written with them; a handler may still override a specific header). Stateless —
`state` points at the immutable config; fully reentrant, no clock, no allocation on the hot path.

## Acceptance / verification

- **Offline unit tests:** with defaults, the middleware sets exactly the expected header set with the
  expected values (assert each); disabling a header omits it; overriding a value works; CSP present
  only when configured; HSTS format correct (`max-age=…; includeSubDomains; preload`).
- **In-process integration (must NOT skip normally):** router+`http.Server`+`http.Client` — a normal
  200 response carries the security headers; a handler that sets its own `X-Frame-Options` wins over
  the default (document precedence).
- `zig build test-security-headers` (or the registered name) + `zig build test` (all) green, Debug +
  ReleaseFast; `zig fmt --check` clean.

## Notes for the implementer

- Use the **zig skill**. Reuse `router.Middleware {state,run}` (state = `*const Config`) and `Ctx`;
  set headers via `ctx.res.setHeader`. No new HTTP logic.
- Header value strings can be precomputed at `init` (e.g. the HSTS string) so the hot path is just
  `setHeader` calls — keep it allocation-free per request.
- Document the precedence (middleware sets, handler may override) and the HTTPS-only note for HSTS.
- SPDX header + a `Provenance:` line (clean-room; design refs helmet.js MIT / OWASP).

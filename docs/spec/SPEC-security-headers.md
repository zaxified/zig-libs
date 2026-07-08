# SPEC — `security-headers`

**Purpose** — Secure-by-default HTTP security response headers as a stateless `router`
middleware: HSTS, CSP (+ Report-Only), `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, `Permissions-Policy`, the Cross-Origin isolation trio (COOP/CORP/COEP) and an
optional `Server` replacement — each individually overridable or disable-able. The hardening
baseline for a directly-internet-facing API.

**Model after / Seed** — Clean-room, no seed project and no third-party code. Model after
helmet.js (MIT; defaults vocabulary and per-header on/off model — no source copied; the
`csp_helmet_default` constant reproduces helmet's default policy *value* as configuration data)
and the OWASP Secure Headers Project (best-practice header catalog). Header semantics themselves
come from the standards: RFC 6797 (HSTS), CSP Level 3, the Fetch/HTML specs (COOP/CORP/COEP), RFC
9110. Design refs in `NOTICE`.

**Design & invariants**
- **Precomputed, stateless, reentrant:** an initialized `SecurityHeaders` is immutable — no clock,
  no allocation, no locks on the hot path (the HSTS value string is formatted once at `init` into
  an embedded buffer). Safe to share across all of `http.Server`'s connection threads.
- **Middleware sets, handler wins:** headers are set on the `ResponseWriter` **before** `next`
  runs, so the handler's head is written with them; `setHeader` replaces by case-insensitive
  name, so a handler (or inner middleware) setting the same header again overrides the default
  exactly once, no duplicates. The `server` replacement value likewise overrides `http.Server`'s
  automatic `Server:` header.
- **Deliberate deviations from helmet defaults:** `X-Frame-Options` is `DENY` (spec mandate;
  helmet defaults to `SAMEORIGIN`); CSP is **off by default** — there is no universally-safe
  policy (a browser-app policy and a JSON-API policy want opposite things), and this module's own
  spec requires "CSP present only when configured" rather than silently shipping either. Two
  ready-made postures ship as constants: `csp_api` (deny-everything, for pure JSON/binary APIs) and
  `csp_helmet_default` (helmet's browser-app default, for servers that also serve HTML). COEP
  (`require-corp`) is off by default, matching helmet — it blocks every embedded cross-origin
  resource that doesn't opt in via CORP/CORS.

**Threat model / out of scope** — Not a WAF or input validator: it only sets response headers, it
never inspects or blocks requests. Known gap: when a handler *errors*, `http.Server` resets the
response to build its own automatic 500 — that plain 500 (and the server's own 431/414/413
replies, which bypass the router entirely) carries no security headers, since the middleware never
gets a chance to run for those responses. HSTS is meaningful only over HTTPS — browsers ignore it
over plain HTTP, so shipping it is harmless there, but deploying it on a host not actually served
via TLS is a caller misconfiguration this module cannot detect (and once cached, browsers refuse
plain-HTTP access for `max-age`, so `preload` is opt-in and effectively permanent). Helmet's
legacy/no-longer-relevant extras (`X-DNS-Prefetch-Control`, `X-Download-Options`,
`X-Permitted-Cross-Domain-Policies`, `X-XSS-Protection: 0`, `Origin-Agent-Cluster`) are
consciously out of scope.

**Verification** — 11 tests (`zig build test-security-headers`). Offline goldens over the
socket-free `http.Server.serveStream`: byte-exact default header set, per-header disable + all-off
bare response, per-header value overrides, CSP/Report-Only opt-in, COEP opt-in, HSTS value for
every flag combination including the `maxInt(u64)` buffer bound, handler-override precedence with
no duplicate header, `Server` replacement over the auto value, 404/405 fallback coverage, bare
`ResponseWriter.apply`. In-process integration (`router` + `http.Server` + `http.Client` over
loopback): a normal 200 carries the full default set and no opt-in headers; a handler that sets its
own `X-Frame-Options` wins — skips only when loopback binding is unavailable.

**Status** — `gap · any · util · reentrant` · deps: `router`, `http`.

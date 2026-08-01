# security-headers — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Precomputed, stateless, reentrant:** an initialized `SecurityHeaders` is immutable — no clock,
  no allocation, no locks on the hot path (the HSTS value string is formatted once at `init` into
  an embedded buffer). Safe to share across all of `http.Server`'s connection threads. Clean-room,
  modeled after helmet.js (MIT; defaults vocabulary and per-header on/off model —
  no source copied, `csp_helmet_default` reproduces helmet's default policy *value* as configuration
  data) and the OWASP Secure Headers Project. Header semantics come from the standards: RFC 6797
  (HSTS), CSP Level 3, the Fetch/HTML specs (COOP/CORP/COEP), RFC 9110 — see NOTICE.
- **Middleware sets, handler wins:** headers are set on the `ResponseWriter` **before** `next` runs,
  so the handler's head is written with them; `setHeader` replaces by case-insensitive name, so a
  handler (or inner middleware) setting the same header again overrides the default exactly once,
  no duplicates. The `server` replacement value likewise overrides `http.Server`'s automatic
  `Server:` header.
- **Deliberate deviations from helmet defaults:** `X-Frame-Options` is `DENY` (spec mandate; helmet
  defaults to `SAMEORIGIN`); CSP is **off by default** — there is no universally-safe policy (a
  browser-app policy and a JSON-API policy want opposite things), so headers are present only when
  configured. Two ready-made postures ship as constants: `csp_api` (deny-everything, for pure
  JSON/binary APIs) and `csp_helmet_default` (helmet's browser-app default). COEP (`require-corp`)
  is off by default, matching helmet — it blocks every embedded cross-origin resource that doesn't
  opt in via CORP/CORS.

## Threat model / out of scope

Not a WAF or input validator: it only sets response headers, it never inspects or blocks requests.
Known gap: when a handler *errors*, `http.Server` resets the response to build its own automatic
500 — that plain 500 (and the server's own 431/414/413 replies, which bypass the router entirely)
carries no security headers, since the middleware never gets a chance to run for those responses.
HSTS is meaningful only over HTTPS — browsers ignore it over plain HTTP, so shipping it is harmless
there, but deploying it on a host not actually served via TLS is a caller misconfiguration this
module cannot detect (and once cached, browsers refuse plain-HTTP access for `max-age`, so `preload`
is opt-in and effectively permanent). Helmet's legacy/no-longer-relevant extras
(`X-DNS-Prefetch-Control`, `X-Download-Options`, `X-Permitted-Cross-Domain-Policies`,
`X-XSS-Protection: 0`, `Origin-Agent-Cluster`) are consciously out of scope.

## Verification

Offline goldens over the socket-free `http.Server.serveStream`: byte-exact default header
set, per-header disable + all-off bare response, per-header value overrides, CSP/Report-Only
opt-in, COEP opt-in, HSTS value for every flag combination including the `maxInt(u64)` buffer bound,
handler-override precedence with no duplicate header, `Server` replacement over the auto value,
404/405 fallback coverage, bare `ResponseWriter.apply`. In-process integration (`router` +
`http.Server` + `http.Client` over loopback): a normal 200 carries the full default set and no
opt-in headers; a handler that sets its own `X-Frame-Options` wins — skips only when loopback
binding is unavailable.

**External anchor, added 2026-08-01**: every test above compares this module's own output
against string literals this module's own author wrote — an in-house re-derivation, not an
external anchor (running `helmet.js` and diffing was considered but is blocked: `node`/`npm`
are not installed on the reference machine). Instead, four goldens compare our precomputed
default/opt-in header VALUES byte-for-byte against short literal example lines copied verbatim
from published third-party documents (not derived from this module): RFC 7034 §2.2.1's own
`X-Frame-Options: DENY` example, RFC 6797 §6.2's own `max-age=31536000` example (the numeric
token; the RFC's own separate `max-age=0; includeSubDomains` example independently proves the
no-space-before-semicolon `includeSubDomains` form is RFC-illustrated, not this module's
invention), and the OWASP Secure Headers Project's own example lines for
`X-Content-Type-Options`, `Referrer-Policy`, `Cross-Origin-Resource-Policy`,
`Cross-Origin-Opener-Policy`, and `Cross-Origin-Embedder-Policy` (`mainsite/01_headers.md`,
Apache-2.0 — see `modules/security-headers/NOTICE`). This is a genuine external anchor for the
headers it covers. **Not covered**: `Content-Security-Policy` — neither RFC 7034/6797 nor the
OWASP page publish a single recommended CSP value string comparable to `csp_helmet_default`
(OWASP's own CSP example is the generic `script-src 'self'`), so `csp_helmet_default` remains
self-anchored; running `helmet.js` itself was ruled out by the missing `node`/`npm`, not attempted.

Run: `zig build test-security-headers`.

## Backlog / deferred

- **500/431/414/413 fallback responses carry no security headers** — a known gap (see threat model
  above): those paths bypass the router/middleware entirely inside `http.Server`. No fix scheduled;
  documented as a caller-visible caveat.
- No other gaps found — the excluded helmet legacy headers are a deliberate non-goal, not a v1 gap.

## Status

`gap · any · util · reentrant` + deps: `router`, `http` — canonical source is `pub const meta` in
src/root.zig.

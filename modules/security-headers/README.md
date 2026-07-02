# security-headers

Secure-by-default HTTP security response headers as a stateless `router`
middleware: HSTS, CSP (+ Report-Only), `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, the
Cross-Origin isolation trio (COOP/CORP/COEP) and an optional `Server`
replacement — each individually overridable or disable-able. The hardening
baseline for a directly-internet-facing API (T5.6 of the Web/API cluster).

Provenance: clean-room — no seed project and no third-party code. Design
references: helmet.js (MIT; defaults vocabulary and per-header on/off model —
no source copied; the `csp_helmet_default` constant reproduces helmet's
default policy *value* as configuration data) and the OWASP Secure Headers
Project (best-practice header catalog). Header semantics from the standards:
RFC 6797 (HSTS), CSP Level 3, Fetch/HTML specs (COOP/CORP/COEP), RFC 9110.

- **Status:** `gap`.
- **Model after:** helmet.js defaults + OWASP Secure Headers Project.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant — an
  initialized `SecurityHeaders` is immutable; no clock, no allocation, no
  locks, no hidden globals. Safe to share across all connection threads.
- **Deps:** `router` (Middleware/Ctx), `http` (`ResponseWriter.setHeader`).

## Import name

Directory `modules/security-headers/`, registered module name
**`security-headers`** — import it as `@import("security-headers")` (module
names are plain strings; the hyphen imports fine, same as the community's
`known-folders`).

## Defaults

`SecurityHeaders.init(.{})` emits, in this order:

| Header | Default value | Knob |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | `hsts` (`?Hsts`) |
| `Content-Security-Policy` | *(off — opt-in)* | `content_security_policy` |
| `Content-Security-Policy-Report-Only` | *(off — opt-in)* | `content_security_policy_report_only` |
| `X-Content-Type-Options` | `nosniff` | `x_content_type_options` (bool) |
| `X-Frame-Options` | `DENY` | `x_frame_options` |
| `Referrer-Policy` | `no-referrer` | `referrer_policy` |
| `Permissions-Policy` | *(off — opt-in)* | `permissions_policy` |
| `Cross-Origin-Opener-Policy` | `same-origin` | `cross_origin_opener_policy` |
| `Cross-Origin-Resource-Policy` | `same-origin` | `cross_origin_resource_policy` |
| `Cross-Origin-Embedder-Policy` | *(off — opt-in, breaks embeds)* | `cross_origin_embedder_policy` |
| `Server` | *(off — replacement value)* | `server` |

Defaults match helmet.js v7 except: `X-Frame-Options` is `DENY` (spec
mandate; helmet uses SAMEORIGIN) and CSP is **off by default** (helmet ships
a default policy; there is no universally-safe one — see below). helmet's
legacy extras (`X-DNS-Prefetch-Control`, `X-Download-Options`,
`X-Permitted-Cross-Domain-Policies`, `X-XSS-Protection: 0`,
`Origin-Agent-Cluster`) are consciously out of scope.

## Usage

```zig
const security_headers = @import("security-headers");
const router = @import("router");

const sh = security_headers.SecurityHeaders.init(.{
    // .hsts = .{ .max_age_s = 63_072_000, .preload = true }, // or null to omit
    .content_security_policy = security_headers.csp_api, // opt-in; see postures below
    // .permissions_policy = "camera=(), microphone=(), geolocation=()",
    // .server = "webserver", // fingerprint reduction
});

var r = router.Router.init(gpa);
defer r.deinit();
try r.use(sh.middleware()); // FIRST middleware, before routes (chi rule)
try r.get("/api/thing", handler);
```

Register it **first** (outermost): the headers are set before the rest of
the chain runs, so short-circuit responses from inner middleware (ratelimit
429, throttle 503, auth 401) and the router's 404/405 fallbacks carry them
too. `apply()` is also public for setting the same header set directly on
any `http.Server.ResponseWriter` without the router.

## Precedence (middleware sets, handler wins)

The middleware sets the configured headers **before** calling `next`, so the
handler's head is written with them. `ResponseWriter.setHeader` replaces by
case-insensitive name — a handler (or inner middleware) that sets the same
header again **overrides** the middleware's default, exactly once, no
duplicates. The configured `server` value likewise replaces `http.Server`'s
automatic `Server:` header.

Known limitation: when a handler *errors*, `http.Server` resets the response
to build its automatic 500 — that plain 500 (and the server's own
431/414/413 replies, which bypass the router) carries no security headers.

## HSTS is HTTPS-only

Browsers ignore `Strict-Transport-Security` received over plain HTTP, so the
header is harmless there — but only deploy it on a host actually served via
TLS: once cached, browsers refuse plain-HTTP access for `max-age` seconds
(and with `include_subdomains`, for every subdomain). `preload` is off by
default; opt in only with `max_age_s` ≥ 1 year, `include_subdomains = true`,
and registration at <https://hstspreload.org> (it is effectively permanent).

## CSP posture (off by default — deliberate)

There is no universally-safe CSP: a browser-app policy and a JSON-API policy
want opposite things, and silently shipping either is worse than making the
choice explicit (this module's spec also requires "CSP present only when
configured"). Two ready-made postures ship as constants:

- `csp_api` — `default-src 'none'; frame-ancestors 'none'; base-uri 'none';
  form-action 'none'` — deny-everything, for pure JSON/binary APIs.
- `csp_helmet_default` — helmet.js v7's browser-app default, when the server
  also serves HTML.

`content_security_policy_report_only` is independent — use it to trial a
stricter policy without enforcing it. Note `X-Frame-Options` is the legacy
anti-clickjacking header; the modern form is CSP `frame-ancestors`, which
overrides `X-Frame-Options` in supporting browsers — keep the two consistent
when you configure a CSP.

## COEP breaks embeds (opt-in)

`Cross-Origin-Embedder-Policy: require-corp` blocks every embedded
cross-origin resource that does not opt in via CORP/CORS. Enable it only
when you need full cross-origin isolation (SharedArrayBuffer,
high-resolution timers); off by default, matching helmet.

## Server header

`server = "..."` replaces the value (fingerprint reduction) on responses
that go through the middleware. Middleware cannot *remove* it — to drop the
header entirely, configure `http.Server` with `.server_name = null`.

## Verification

`zig build test-security-headers` — offline goldens over the socket-free
`http.Server.serveStream` (byte-exact default header set, per-header
disable + all-off bare response, per-header value overrides, CSP/Report-Only
opt-in, COEP opt-in, HSTS value for every flag combination incl. the
maxInt(u64) buffer bound, handler-override precedence with no duplicate
header, Server replacement over the auto value, 404/405 fallback coverage,
bare-`ResponseWriter` `apply`), plus an in-process integration run
(`router` + `http.Server` + `http.Client` over loopback: a normal 200
carries the full default set and no opt-in headers; a handler that sets its
own `X-Frame-Options` wins) that only skips when loopback binding is
unavailable.

# SPEC — `cors`

**Purpose** — Cross-Origin Resource Sharing as a global `router` middleware: preflight (`OPTIONS`
+ `Access-Control-Request-Method`) interception with a bodyless 204, and `Access-Control-*` header
injection on actual cross-origin requests.

**Model after / Seed** — Clean-room, no seed project and no third-party code. Model after rs/cors
(Go, MIT — the primary behavioral model: preflight always intercepted, origin/method/header gates,
failed preflight = 204 without CORS headers) and expressjs/cors (MIT — the reflect-request-headers
default). Protocol semantics from the WHATWG Fetch standard (CORS protocol) and RFC 9110. Design
refs in `NOTICE`.

**Design & invariants**
- **Immutable, reentrant:** an initialized `Cors` has no clock, no locks, no hidden globals; the
  only allocation is the init-time join of the configured lists (freed by `deinit`). The hot path
  reflects borrowed request slices only — safe across all of `http.Server`'s connection threads.
- **Preflight always intercepted:** `OPTIONS` with `Access-Control-Request-Method` gets 204, no
  body, handler never runs — regardless of whether the origin is allowed or a route exists. CORS
  headers appear only when origin + requested method + requested headers all pass; a failed
  preflight is still 204, just without them (how the browser learns "no"). Every intercepted
  preflight carries `Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers`.
- **Actual requests always continue down the chain:** CORS never blocks server-side handling — it
  only withholds the headers that let a cross-origin script *read* the response. Headers are set
  when `Origin` is present + allowed **and** the method is in `allowed_methods`; `.any` emits the
  literal `*`, a list/predicate match echoes the specific origin plus `Vary: Origin`. Origin
  matching is an exact byte compare (or a caller predicate) — no normalization, so the caller must
  configure the canonical serialization browsers send (lowercase scheme + host, no trailing slash).
- **Secure default, deliberately not rs/cors's:** `allowed_origins` defaults to `.none` — no CORS
  headers at all until origins are explicitly configured (rs/cors defaults to permissive `*`).
  `allowed_headers` defaults to `.reflect` (echo `Access-Control-Request-Headers`), matching
  expressjs rather than rs/cors's fixed list, since header *names* aren't sensitive and the origin
  gate remains the real security boundary.
- **Credentials vs. wildcard rejected at construction:** the Fetch standard forbids
  `Access-Control-Allow-Origin: *` on credentialed responses, and the common workaround
  (reflect-any-origin + `Allow-Credentials: true`) grants every website credentialed access.
  `Cors.init` rejects `.any` + `allow_credentials = true` with
  `error.CredentialsWithWildcardOrigin` rather than silently downgrading; a `.predicate` that
  returns true is the explicit, greppable opt-in to that footgun.

**Threat model / out of scope** — CORS is a browser-enforced contract, not a server-side
access-control mechanism: it never blocks a request from executing server-side, only whether a
cross-origin script may read the response — it must not be used as an authorization boundary.
Exact-byte origin matching means case/trailing-slash/port mismatches silently fail to match
(documented, not a bug); normalization is the caller's job. A handler that sets `Vary` itself
replaces (not merges) the middleware's value. rs/cors's `OptionsPassthrough` (letting intercepted
preflights fall through to app-defined `OPTIONS` routes) and `Access-Control-Allow-Private-Network`
are out of scope for now.

**Verification** — 14 tests (`zig build test-cors`). Offline goldens over the socket-free
`http.Server.serveStream`: byte-exact 204 preflight with the full header set + handler-not-invoked
proof; `.reflect` echo + absent-ACRH omission; each failing gate → 204 with `Vary` and zero CORS
headers, including the byte-compare case-sensitivity check; preflight interception on would-be 405
and 404 paths; plain `OPTIONS` routing normally with actual-request headers; actual-request echo +
`Vary: Origin` + credentials + exposed headers; `.any` → `*` without `Vary`; disallowed/absent
Origin and `.none` passthrough with the handler still running; the actual-request method gate;
predicate origins on both request shapes; `*` + credentials init rejection; `max_age_s` 0/max
formatting and the join precomputations. In-process integration (`router` + `http.Server` +
`http.Client` over loopback): preflight `OPTIONS` → 204 + CORS headers with the handler never
invoked; `GET` with an allowed `Origin` → `Access-Control-Allow-Origin` + `Vary`; a disallowed
origin → no CORS headers — skips only when loopback binding is unavailable.

**Status** — `gap · any · util · reentrant` · deps: `router`, `http`.

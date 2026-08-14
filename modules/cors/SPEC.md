# cors — spec

Cross-Origin Resource Sharing as a global `router` middleware. Usage: see ./README.md.
Attribution/provenance: see /NOTICE.

## Design & invariants
- **Immutable, reentrant:** an initialized `Cors` has no clock, no locks, no hidden globals; the
  only allocation is the init-time join of configured lists (freed by `deinit`). The hot path
  reflects borrowed request slices only — safe across all connection threads.
- **Preflight always intercepted:** `OPTIONS` with `Access-Control-Request-Method` gets 204, no
  body, handler never runs — regardless of origin/route validity. CORS headers appear only when
  origin + requested method + requested headers all pass; a failed preflight is still 204 without
  them. Every intercepted preflight carries `Vary: Origin, Access-Control-Request-Method,
  Access-Control-Request-Headers`.
- **Actual requests always continue down the chain:** CORS only withholds the headers that let a
  cross-origin script read the response. Headers set when `Origin` present + allowed and method in
  `allowed_methods`; `.any` emits `*`, a list/predicate match echoes the origin + `Vary: Origin`.
  Origin matching is exact byte compare (or caller predicate) — no normalization.
- **Secure default, deliberately not rs/cors's:** `allowed_origins` defaults to `.none` (rs/cors
  defaults to permissive `*`); `allowed_headers` defaults to `.reflect` (matches expressjs).
- **Credentials vs. wildcard rejected at construction:** `Cors.init` rejects `.any` +
  `allow_credentials = true` with `error.CredentialsWithWildcardOrigin` rather than silently
  downgrading; a `.predicate` returning true is the explicit, greppable opt-in.

## Threat model / out of scope
CORS is a browser-enforced contract, not a server-side access-control mechanism: it never blocks a
request from executing server-side, only whether a cross-origin script may read the response — must
not be used as an authorization boundary. Exact-byte origin matching means case/trailing-slash/port
mismatches silently fail to match (documented, not a bug); normalization is the caller's job. A
handler that sets `Vary` itself replaces (not merges) the middleware's value — unfixable inside this
module, since `http.Server.ResponseWriter` exposes neither an append (`addSetCookie` is
Set-Cookie-only) nor a way to read a set response header, so there is nothing to merge WITH, before
or after `next`. Consequence: the per-origin `Access-Control-Allow-Origin` ships with a `Vary` that
no longer names `Origin`, which a shared cache can turn into a cross-origin response mix-up; the
caller-side rule is that a handler setting `Vary` on a CORS route lists `Origin` too. Both the
hazard and the safe shape are pinned by a test, so an `http` append primitive would arrive with a
red assertion pointing at the fix. rs/cors's `OptionsPassthrough` and
`Access-Control-Allow-Private-Network` are out of scope for now.

## Verification
`zig build test-cors`. Offline goldens over the socket-free `http.Server.serveStream`:
byte-exact 204 preflight + handler-not-invoked proof; `.reflect` echo + absent-ACRH omission; each
failing gate → 204 with `Vary` and zero CORS headers incl. case-sensitivity; preflight interception
on would-be 405/404; actual-request echo + `Vary: Origin` + credentials + exposed headers; `.any` →
`*` without `Vary`; disallowed/absent Origin passthrough; the actual-request method gate; predicate
origins; `*`+credentials init rejection; `max_age_s` formatting. In-process integration (`router` +
`http.Server` + `http.Client` over loopback): preflight → 204 + CORS headers with handler never
invoked; allowed-origin `GET` → headers + `Vary`; disallowed origin → no CORS headers — skips only
when loopback binding is unavailable.

## Backlog / deferred
None.

## Status
`gap · any · util · reentrant` + deps: `router`, `http` — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/root.zig:1176/1203/1225 compare against flask_cors 6.0.5 run once as a black-box oracle, with an 8-item divergence ledger judged against Fetch/RFC 9110; the other 19 preflight/actual tests are still this module's own assertions about its own output

**How it got there.** The anchoring work landed. DONE 9dee82e: flask_cors oracle; its wildcard+credentials default is the unsafe one

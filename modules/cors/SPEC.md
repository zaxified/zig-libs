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

## Static CORS (deliberate deviation, comptime)

The second named posture, for the same adoption reason as the wildcard one below: a public
read-only API whose grant is a **build-time constant** — one `Access-Control-Allow-Origin` value
(`*` or one fixed origin) stamped on every response and every preflight, regardless of `Origin`.
No gates run, and the policy compiles to `setHeaderStatic` slot writes. `Vary` is emitted only on
the one path that genuinely varies: a preflight with `allow_headers = null` echoes the request's
`Access-Control-Request-Headers`, so it carries `Vary: Access-Control-Request-Headers`. Pin
`allow_headers` and the posture is constant end to end and emits no `Vary` at all. Surface: `StaticOptions` + `applyActualStatic` /
`applyPreflightStatic` / `isPreflight` — no `Cors`, no `init`, no allocator. `allow_credentials`
is structurally absent: a constant grant with credentials is the combination `Cors.init` rejects,
so the knob does not exist. First consumer: qap (its `Config.cors` is this type).

## Unconditional wildcard CORS (deliberate deviation, opt-in)

Spec-correct CORS — the default, unchanged — never touches a response the browser isn't asking a
CORS question about: no `Origin` header means no CORS headers, and a plain `OPTIONS` with no
`Access-Control-Request-Method` is not a preflight, it routes normally. That is correct and stays
the default. It is also, on its own, a hard migration wall for one real shape of existing API: one
that has always answered *every* `OPTIONS` with 204 and stamped `Access-Control-Allow-Origin: *` on
*every* response, regardless of `Origin`. Such an API cannot adopt this module without changing what
is on the wire — and "adopting this changes your API's shape" is the most common reason a library
meant for outside consumers doesn't get adopted.

`Options.allow_unconditional_wildcard` (default `false`) is the escape hatch, named so the deviation
is visible at the call site rather than reading like an ordinary feature flag. It requires
`allowed_origins = .any` — enforced at `Cors.init` with `error.UnconditionalWildcardRequiresAnyOrigin`
— because the option's entire meaning is "wildcard on every response"; paired with `.list`/
`.predicate`/`.none` it would have nothing coherent to gate on. When true: `applyActual` sets
`Access-Control-Allow-Origin: *` unconditionally (dropping the `Origin`-presence and
`allowed_methods` gates), and `middlewareRun` intercepts every `OPTIONS`, ACRM or not, through the
same `handlePreflight` path (which itself skips the origin/method/header gates for the same reason).

**One field, not two — the two behaviours (unconditional emission; bare-`OPTIONS` interception) are
bundled deliberately.** They read as independent (a consumer could imagine wanting either alone),
but they are two symptoms of one underlying posture: a legacy CORS gate that never conditioned on
`Origin` in the first place. Splitting them into separate flags would let a consumer enable only
one half and still hit the exact problem the option exists to solve — the wire shape changing for
the *other* kind of request (e.g. unconditional headers on GET/POST but a bare `OPTIONS` still
falling through to a 404/405, or vice versa). One field keeps the migration atomic and keeps the
whole posture a single grep target (`rg allow_unconditional_wildcard`).

## Header timing vs. `ResponseWriter.reset()`

`middlewareRun` calls `applyActual` **before** `next.run` — CORS headers land on the response before
the handler chain executes. That is deliberate, not an oversight: `http.Server.ResponseWriter`
buffers a response until the first body write (or an explicit streaming opt-in) commits the head, and
`setHeader`/`reset` both fail `error.HeadersSent` once that has happened. Moving `applyActual` to
*after* `next.run` (evaluated and rejected — see below) would fail exactly that way for any handler
that streams its body, which `cors` cannot assume no route does.

The consequence: an *outer* middleware that calls `ResponseWriter.reset()` after `next.run` — e.g. to
replace a `text/plain` denial body with JSON — wipes every header `cors` set, `reset` clears the
header list wholesale, and there is no way for `cors` to see that happen or be asked again
automatically. `http.Server.ResponseWriter` has no snapshot/restore and no header-read primitive
(the same gap the `Vary`-clobber hazard above lives on), and that lives in `http`, out of scope here.

**The fix lives entirely inside `cors`: `applyActual` is `pub`.** A response-rewriting middleware
calls `your_cors.applyActual(ctx.req, ctx.res)` again immediately after its own `reset()`, before
writing the new body — the exact same gate, idempotent, safe to call twice. This is documented as
the concrete rule in README.md rather than left as "reapply the headers somehow": the alternative
(the outer middleware reimplementing the origin/method gate itself) would drift the moment `cors`'s
gate logic changes.

**Considered and rejected: swap the ordering (apply after `next.run` instead of before).** This is
the "ordering" fix the task brief flags as worth evaluating. It was rejected because it is not a
pure reordering — it changes what a streaming handler experiences. `next.run`'s completion does not
imply the head is still unsent: a streaming handler (chunked/SSE-style responses) can commit the head
partway through its own body, and `applyActual` running afterward would then return
`error.HeadersSent`, which propagates as an unhandled `anyerror` — a 500 on a route that previously
worked, on *every* request to it, not just ones behind a `reset()`-calling outer middleware. That
regression is strictly worse than the one being fixed (which only bites when a specific pattern of
outer middleware is present) and it cannot be scoped away, since `cors` is deliberately router-agnostic
about what any given handler does. Default ordering stays as-is.

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
origins; `*`+credentials init rejection; `allow_unconditional_wildcard` requires `.any` (init
rejection) and, once set, emits the wildcard on an Origin-absent actual request and intercepts a
bare `OPTIONS` with 204 (both cases also golden the default's unchanged behavior alongside);
`max_age_s` formatting. In-process integration (`router` + `http.Server` + `http.Client` over
loopback): preflight → 204 + CORS headers with handler never invoked; allowed-origin `GET` →
headers + `Vary`; disallowed origin → no CORS headers — skips only when loopback binding is
unavailable.

## Backlog / deferred
None.

## Status
`gap · any · util · reentrant` + deps: `router`, `http` — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/root.zig:1326/1353/1375 compare against flask_cors 6.0.5 run once as a black-box oracle, with an 8-item divergence ledger judged against Fetch/RFC 9110; the other 22 preflight/actual tests (19 plus the 3 added for `allow_unconditional_wildcard`) are still this module's own assertions about its own output — flask_cors has no equivalent posture to anchor the deviation against

**How it got there.** The anchoring work landed. DONE 9dee82e: flask_cors oracle; its wildcard+credentials default is the unsafe one

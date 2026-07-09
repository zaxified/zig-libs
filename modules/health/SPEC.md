# health — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Liveness always answers 200 — a bare "the server can run this handler" check; this module never
fails liveness, since a liveness failure/no-response is what tells the orchestrator to restart, so
the check itself has nothing to evaluate. Readiness answers 200 when every registered `Check`
passes, else 503 with a `not ready: <name>` line per failing check in the body. A middleware, not
handlers: a `router.Handler` is a stateless fn pointer with no per-instance state, so `Health` owns
the config (checks, paths) and intercepts the two probe paths, passing every other path through
unchanged. Register order matters: before auth/rate-limit middleware, so an orchestrator's probe
(which cannot present a bearer token) is never gated. Zero allocation: the failing-check listing is
assembled on the stack and written through the response writer. Concurrency: config is immutable
after init (threadsafe); readiness is only as thread-safe as the caller's `Check.checkFn`, which
runs on the connection thread — callers are told to keep it a non-blocking, thread-safe atomic-flag
load. Clean-room from the documented Kubernetes liveness/readiness probe model and the conventional
`/healthz`–`/readyz` endpoints; no seed, no NOTICE entry beyond the public k8s convention itself.

## Threat model / out of scope
Not a security boundary: the probe paths are intentionally unauthenticated (an orchestrator has no
token to present), so anything reachable on `/healthz`/`/readyz` should be information an
unauthenticated caller may see (check *names*, not internal detail). Does not implement startup
probes, custom probe protocols (gRPC health, TCP), or dependency polling/caching — `Check`
callbacks are called synchronously on every `/readyz` hit and must already be cheap (an atomic
flag), not a live database ping.

## Verification
4 offline tests through `http.Server.serveStream`: liveness always-200 + pass-through of other
paths, readiness 200/503 with the failing-check listing, the empty-checks default (no checks
registered → always ready), custom probe paths. Green in Debug + ReleaseFast. Run: `zig build
test-health`.

## Backlog / deferred
None recorded in PLAN.md beyond its place in the "prod-API hardening + nice-to-have cluster"
(requestid/health/conditional/multipart/cookies/...) — no per-module gap noted.

## Status
`gap · any · util · threadsafe` · deps: `router`, `http` — canonical source is `pub const meta` in
src/root.zig.

# requestid — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-requestid`, kept instrument kind 3): card Performance 0.15–0.24× go-chi/chi RequestID (net of the HTTP stack), measured on a quiet host. Tooling only, no code change.

- **2026-10-04** — **Tests:** mutation run (12 schemata mutants, all killed after two new tests:
  `current()` null on a fresh thread, `generateInto`'s counter field steps by one). No code change.

- **2026-08-31** — `isAdoptable` (whether an incoming ID would be adopted)
  and `generateInto` (a fresh ID into a caller-owned buffer, nothing
  request-scoped kept) are public, for callers outside the middleware.
  (Entry added 2026-09-26: the change shipped without one.)
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on nginx
  `$request_id`, Envoy `x-request-id`, chi `middleware.RequestID` (design reference, not
  a test anchor).
- **2026-07-08** — New module: Request/correlation-ID middleware — adopt incoming
  `X-Request-Id` or generate, echo on the response, expose via `current()` (composes
  with auth).

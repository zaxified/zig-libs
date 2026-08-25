# health — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-25** — Added: `Health.probeFor` + `Health.respond`, so a server that routes
  itself can use the probe contract without building a `router.Ctx` it has no other use
  for. Same shape `metrics.Registry.respond` already had; both entry points go through
  the same two functions, and a test pins that they write identical bytes.

- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Kubernetes
  liveness/readiness probe convention (`/healthz`, `/readyz`); chi/Envoy health handlers
  (design reference, not a test anchor).
- **2026-07-08** — New module: Liveness (`/healthz`) + readiness (`/readyz`) probe
  middleware — 200/503 from registered dependency checks (k8s probe contract).

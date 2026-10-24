# health — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-11** — Added (S2, closes the survey gaps against alexliesenfeld/health v0.8.1): an opt-in startup probe (`Health.startup = .{ .started = &flag }`, path `/startupz` by default; 503 `not started` until the application sets its own atomic flag) and an opt-in JSON body (`Health.json`; `{"status":"up"|"down","details":{"<check>":{"status":...}}}` with `application/json; charset=utf-8`, still governed by `detail`, names escaped, no allocation; `details` lists at most 256 checks). `Probe` gains `.startup`. Tests: startup + JSON goldens and an extended model-fuzz. New `tools/bench.zig` + `tools/go_bench` (`zig build bench-health`).

- **2026-10-11** — tests: seeded model-fuzz comparing random configs and requests against a naive probe/body/call-count reference model. No API or behaviour change.

- **2026-10-04** — **Tests:** mutation run (12 schemata mutants, 11 killed, 1 equivalent; one new
  test pins the 512-byte detail budget edge, the truncation marker and `no-store` on a 503).
  No code change.

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

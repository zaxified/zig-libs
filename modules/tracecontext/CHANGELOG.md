# tracecontext — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on
  OpenTelemetry propagators (Go `go.opentelemetry.io/otel/propagation`), W3C Trace
  Context Level 1 spec (design reference, not a test anchor).
- **2026-07-08** — New module: W3C Trace Context — `traceparent`/`tracestate` parse +
  generate + a propagation middleware (child span per hop, `current()`) for distributed
  tracing.

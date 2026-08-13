# resilience — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on resilience4j (composition +
  breaker states + semaphore Bulkhead) + Polly (consecutive-failure trip) + AWS
  full-jitter backoff (design reference, not a test anchor).
- **2026-07-02** — New module: Circuit breaker + retry/backoff + timeout + bulkhead
  (concurrency limiter) for calling upstreams (generic).

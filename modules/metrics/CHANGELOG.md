# metrics — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-16** — A1 fix campaign, F4 (performance, concurrency):
  `AccessLog.log` with `synchronized = true` no longer holds its spinlock
  across `writer.flush()`. Every other request thread used to spin for the
  whole write syscall: into a plain file, 25.4 µs of CPU per line at 8
  threads against 1.47 µs at one, and a slower sink scaled that up with it.
  Concurrent calls now share the writer through a group commit: a line is
  formatted under the lock into an inline pending batch; at most one call
  (the flusher) touches `writer`, with the lock released, swapping each
  batch out before writing it; a line too long for a batch is written whole
  by its own caller once it owns the writer; and the flusher hands the role
  to a caller waiting on a full batch, so no single request writes everyone
  else's lines indefinitely. Lines are still never torn and keep per-thread
  order; when no call is in flight every line has been written and flushed,
  so there is still no `deinit`. Public API unchanged; `AccessLog` grows by
  its two 4 KiB batch buffers. Measured (ReleaseFast, 7 interleaved reps,
  file sink, CPU per line before/after per rep): 2 threads 3.35× (2.58–3.96),
  4 threads 3.44× (3.23–4.01), 8 threads 3.02× (2.61–6.66), 1 thread 0.99×
  (noise); with a 0.2 ms sink at 8 threads 17.9× (5.66–29.2).
- **2026-09-12** — A1 fix campaign round 2, decision Q1 (this module's only
  in-repo consumers are `modules/metrics/example` and
  `example-apps/http-service`, which the burndown's "konz." column does not
  see — treated as "no consumer", so the norm wins even where it rejects
  input accepted today):
  - **BEHAVIOURAL:** F3 — `AccessLog`'s JSON writer now guarantees valid
    JSON *and* valid UTF-8 for any input bytes. HTTP/2 does not bound
    `:path` to printable ASCII the way HTTP/1.1 does (`h1.zig:438` vs.
    `h2_server.zig:1416-1419`), so a byte outside UTF-8 was reachable in
    `entry.path` from the wire and produced a `.json` line `std.json`
    rejected, falsifying the module's own repository-wide fuzz exemption
    ("there is no path from a socket" to a byte-accepting function — true
    of `Registry.counter`/`gauge`/`histogram`, false of this path). Fixed
    at the writer, not in `http`: RFC 9110's obs-text permits 0x80-0xFF in
    a field value, so `http` is right not to reject it. A byte that is not
    part of a valid UTF-8 sequence is now replaced with U+FFFD, one byte at
    a time; a valid multi-byte sequence still passes through unchanged.
  - **BEHAVIOURAL, new `RegisterError` variants:** F5 — a histogram's
    derived sample names (`<name>_bucket`/`_sum`/`_count`) are now reserved
    against a different family taking the same name, in either
    registration order (`RegisterError.NameCollision`) — previously two
    same-named, different-valued samples could reach the same exposition,
    which Prometheus's scrape parser rejects outright, blinding every
    other family too. F6 — a label value or HELP text that is not valid
    UTF-8 is now rejected at registration (`RegisterError.InvalidUtf8`)
    instead of reaching the wire and breaking the exposition's own
    `charset=utf-8` promise. F13 — `le` and `quantile` are now reserved
    label names on every instrument kind, not just histograms
    (`RegisterError.ReservedLabelName`); previously `le` was accepted on a
    counter or gauge, which is exactly the mechanism F5's collision needed.
  - **BEHAVIOURAL:** F9 — `RequestMetrics.init` now touches the request
    counter and latency histogram families, as its own doc comment already
    promised, not just the in-flight gauge. A name collision with a family
    the application registered first now fails at `init`, matching the
    documented "misconfiguration fails here, not mid-request" — before
    this fix, such a collision returned success and silently, permanently
    disabled the request counter or histogram, with no error anywhere.
  - **Documentation, no behavior forced:** F12/R3 — the recommended
    middleware order around `/metrics` flips: register `RequestMetrics`
    before `Endpoint` by default, so a scrape is measured like any other
    request (closes the one blind spot a scrape flood otherwise leaves in
    telemetry, see F2/F8 below). Registering `Endpoint` first remains a
    fully supported, explicit opt-out (uncounted scrapes, request-rate
    numbers the scrape interval cannot skew) and stays covered by its own
    tests.

  scripts/modtest metrics: 38/38 (Debug; was 32/32 before this batch).

- **2026-09-11** — A1 fix campaign, F15's last three mutations (M29, M31,
  M32) get regression coverage (test-only, no production behavior change).
  A prior pass left these open, reasoning that proving `writeText`/
  `getOrRegister`/`AccessLog.log` actually take their spinlock needed either
  a flaky race (the critical sections are too short for natural interleaving
  to catch it, which is why the module's own existing stress tests missed
  all three mutations) or production code changed just for testability.
  Neither is necessary: the new tests take the lock from the TEST itself
  before the function under test runs, so a correctly-locking function has
  no choice but to spin until the test releases it, observed via a 50ms
  window and an atomic "done" flag -- deterministic, not probabilistic.
  Verified against all three mutations named in the audit (temporarily
  removing each `lockSpin`/`unlock` pair and confirming exactly the matching
  new test fails, 31/32, with the other 31 unaffected; reverted). F15 is now
  closed in full (6/6 named mutations have a regression test). Zero
  production lines touched.

  scripts/modtest metrics: 32/32 (Debug and ReleaseFast).

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `RequestMetrics`'s
  `.status = .code` granularity and any registry with many unrelated metric
  families are both cheaper — `getOrRegister`'s family lookup was O(registry
  size) per call (measured: 8000 families, 50.47us -> 0.03us, 1802x); a scrape's
  transient exposition buffer now pre-sizes from the previous scrape instead of
  growing from zero (measured: 20000-series registry, peak transient 1.17x ->
  1.00x the exposition size). No output changed, no API changed — `Registry`
  gained two internal fields (a name->family index, a size hint), both purely
  additive. Also: three false doc claims corrected (lock-free-hot-path and
  "still bounded" language now distinguish `.status = .class`/`.code`; UTF-8
  and escaping doc comments no longer overclaim what the code enforces), and
  three previously-untested code paths (an `.identity`-framed response's byte
  count, a backwards-moving clock, and JSON range-control-byte escaping) now
  have regression tests — the code in all three cases was already correct.
- **2026-09-09** — Licensing correction, no code change. `NOTICE` said the reproduced
  Prometheus exposition-format excerpt "adds no condition beyond MIT's own". It is
  Apache-2.0 material, so that was untrue when written: §4(a) asks that a copy of the
  License travel with it, and — uniquely among this repository's Apache upstreams —
  `prometheus/docs` ships a `NOTICE` (388 B), so §4(d) genuinely applies. The License is
  now reproduced in full, upstream's NOTICE is propagated verbatim, and the two omitted
  sections of the excerpt are stated as the §4(b) notice of change. The obligation has
  been in force since the excerpt was committed; only the record was wrong.
- **2026-07-19** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on Prometheus `client_golang`
  (registry/instrument semantics) + text exposition format 0.0.4 (design reference, not
  a test anchor).
- **2026-07-02** — New module: Prometheus registry (counter/gauge/histogram) +
  `/metrics` + request middleware + access-log writer (combined/JSON).

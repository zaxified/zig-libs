# tracecontext — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Test-only: all five real `traceparent` headers in the fuzz
  corpus arrived at the parser as the empty string.** `buildTraceparent` opened
  with `smith.valueRangeAtMost(u8, 0, 7)` to choose between "arbitrary bytes"
  and "assemble the four fields". A ranged `Smith` draw reads EIGHT octets as a
  little-endian `u64` and returns the range MINIMUM unless that whole word
  already lies inside the range — `"00-4bf92"` is nowhere near 0..7 — so every
  seed took the arbitrary-bytes branch, `smith.bytes(&raw)` ate the rest of the
  header, and the ranged length after it found nothing left and returned 0.
  Measured 2026-09-07: **0 of 5 seeds carried an octet to `TraceParent.parse`
  and 0 parsed.** The harness now makes one `smith.slice` draw and reads the
  seed as a script whose first octet selects "the rest is the header verbatim"
  — which is what lets a real W3C example be a seed at all — or "the rest is a
  field-assembly script", read through `testkit.fuzz.Cursor`. Corpus 5 → 16,
  adding uppercase hex (which the spec forbids), an `_` delimiter, and
  `header_len` off by one in both directions. Measured after: **15 of 16 seeds
  non-empty, 788 octets handed to the parser, 4 headers parsed, 2 of them with
  the sampled flag set.**

- **2026-08-14** — `zig build check-fuzz` coverage: a `testing.fuzz` harness on
  `TraceParent.parse` (the `traceparent`-header decode entry point), generating both
  arbitrary bytes and traceparent-shaped input with each field's length, hex-ness and
  delimiter independently perturbed, plus a small corpus of the known edge cases
  (all-zero trace-id/parent-id, reserved version `ff`, future-version extension).
  Allocation-free, so this is a never-panics harness, not a leak oracle. No panic, hang
  or leak found.
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on
  OpenTelemetry propagators (Go `go.opentelemetry.io/otel/propagation`), W3C Trace
  Context Level 1 spec (design reference, not a test anchor).
- **2026-07-08** — New module: W3C Trace Context — `traceparent`/`tracestate` parse +
  generate + a propagation middleware (child span per hop, `current()`) for distributed
  tracing.

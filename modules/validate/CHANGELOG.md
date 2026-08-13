# validate — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-28** — Security audit: the module's untrusted-input surface gained fuzz
  harnesses — `fuzzValidateJson` and `fuzzValidateFormat` (the latter across all 12
  formats) — which it had none of, unlike the sibling wire parsers. Tests only.
- **2026-07-21** — **BEHAVIOURAL, not breaking** — two audit findings fixed. `min_len` /
  `max_len` counted **bytes** while the emitted message said "characters", the module doc
  said "string chars" and the modeled reference (pydantic v2) counts code points; they now
  count Unicode code points, and a string carrying invalid UTF-8 fails closed with
  `string_unicode` when a length rule applies. Separately, `numValue` did `parseFloat(s)
  catch 0` on a `.number_string`, so a value that cleared the JSON number grammar but
  failed to parse was silently compared against `min`/`max` as `0`; it now returns `?f64`
  and the call site emits a validation error instead.
- **2026-07-19** — Security audit (HIGH, reproduced). Error aggregation was **O(n²)**:
  `Builder.append` linearly scanned every error collected so far to dedupe on each append,
  so a request body that complies with the default structural limits (≤10 000 array
  elements) but fails a per-element rule burned ~196 ms of CPU in ReleaseFast and 3.2 s in
  Debug, scaling quadratically — a remotely triggerable CPU-exhaustion DoS against any
  schema with a constrained array or object field. The per-append scan is gone (the
  single-pass validator produces no duplicates), the one genuine duplicate source is
  deduped once via `dedupeFrom`, and a hard `max_errors = 1000` cap bounds both sides, so a
  report is now linear and capped rather than quadratic and unbounded. The audit raised
  four findings in total and all four were fixed; the other three are the entries above.

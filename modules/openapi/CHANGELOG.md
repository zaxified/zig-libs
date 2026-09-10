# openapi — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **BEHAVIOURAL, not breaking:** Two `RouteDoc.Response`s sharing a `status`
  used to both get written into the generated document, producing a duplicate JSON object
  key that `std.json` — the parser this module uses everywhere, including its own docs page
  — refuses to re-read (`error.DuplicateField`), contradicting this module's own doc comment
  ("duplicate JSON keys are never emitted"). Now dedupes, first registration wins — same rule
  `writePathParameters` already applies to a duplicate path-parameter name (F6). The pre-fix
  output was not valid JSON at all, so no well-formed behavior is being taken away (wave-2
  audit finding F3).
- **2026-09-10** — **BEHAVIOURAL, not breaking:** A `/openapi.json` request that hits a
  route with a malformed `request_schema` used to redo the FULL document build, under a
  pure spinlock, on every single request forever (compounding to O(N²) CPU under
  concurrency — one malformed schema could cost tens of seconds of CPU for a handful of
  unauthenticated requests). Both the successful AND the failed build are now cached, and
  the build runs outside the lock, so this degrades to "the same error, cheaply" instead
  of "the same expensive failure, forever". Path/method grouping is now O(routes) instead
  of O(routes²) (unchanged output, just faster on large route tables). A route pattern
  that captures the same parameter name twice no longer emits a duplicate OAS parameter
  entry. The response now carries a strong `ETag`; a matching `If-None-Match` gets `304`
  instead of the full body. README/SPEC.md corrected to describe the actual
  build-once-and-cache concurrency model (they still described the pre-2026-08
  per-request-regeneration behavior).
- **2026-09-09** — Licensing correction, no code change. `NOTICE` said the reproduced
  OpenAPI `webhook-example.json` "adds no condition beyond MIT's own" and pointed the
  reader at upstream's `LICENSE` file — a file that is not in this tree, so a consumer
  who received only zig-libs got no copy of the licence at all. Apache-2.0 §4(a) is now
  discharged by reproducing the License in full. §4(b) records that the document is
  byte-for-byte unmodified; §4(d) records that upstream ships no `NOTICE` (HTTP 404,
  re-verified 2026-09-09), so nothing propagates.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on FastAPI auto-docs
  (Python), utoipa (Rust) (design reference, not a test anchor).
- **2026-07-03** — New module: OpenAPI 3.1 spec generated from the route table +
  `/openapi.json`.

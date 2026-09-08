# openapi — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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

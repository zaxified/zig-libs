# requestid — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-29** — **NO CONSUMER-VISIBLE CHANGE:** Delta audit of the no-panic sweep: 1 mutant over the best-effort echo (budget errors re-propagated): 1/1 killed on the first run. Card A1 again.
- **2026-10-29** — **Behaviour change (fix):** the response echo of the ID is best effort: when an outer middleware already filled the response header table or header-byte budget, the echo is skipped instead of failing the request with a 500 (`current()` still has the ID). No-panic sweep + blind review (§ GJ).
- **2026-10-24** — **Behaviour change (fix):** an adopted ID is copied into the thread-local buffer, so
  `current()` never points into a request head the next request overwrites; it keeps the last ID after the
  request (an access log outside the middleware reads it). **Behaviour change:** `RequestId.middleware()`
  panics on an `Options.header_name` that is not an RFC 9110 token or is `Content-Length`/
  `Transfer-Encoding` (every echo failed or vanished before). Docs: the echo can still fail on a full
  response header table; a `fork()` child repeats IDs the parent generated before forking. Tools: the
  bench gains a tower-http 0.7.1 side (`tools/rust_fast_bench`, `BENCH_FAST=0` skips it); `tools/lead_probe`
  shows chi adopting hostile incoming IDs verbatim. Grade 1.

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** tools ported to Zig 0.17.0 (compile only): `tools/bench.zig`: `std.ascii.indexOfIgnoreCase` -> `findIgnoreCase`.
- **2026-10-11** — Generated IDs are now unique within the process across threads: 16 hex of a per-process prefix + 16 hex of a process-wide atomic sequence (was monotonic ns · thread-address nonce · per-thread counter, which could repeat across connection threads). The ID is still 32 lowercase hex; its fields changed. New `Options.generator` (`Generator`: context + function) for a caller's ID scheme; an output that fails `isAdoptable` or lies outside the buffer falls back to the built-in ID. README charset and test count corrected.

- **2026-10-11** — tests: seeded model-fuzz against a naive adopt-or-generate reference model (`isAdoptable` on random bytes; the middleware over random options, headers and lengths). No API or behaviour change.

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

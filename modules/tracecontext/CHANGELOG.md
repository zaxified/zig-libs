# tracecontext — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-29** — **NO CONSUMER-VISIBLE CHANGE:** no-panic sweep + blind review (§ GJ) found no data-reachable defect; the monotonic seed clock wraps instead of overflowing; TC-1 (header-name validation) in Backlog.
- **2026-10-24** — **Behaviour change (fix):** the echo of `traceparent`/`tracestate` on the response is best effort — a response header table already full no longer fails the request. **Behaviour change (fix):** the middleware's own `state_entry` member is never the one dropped when the outgoing `tracestate` overflows 512 bytes (new `TraceState.writeKeeping`; `write` unchanged). Docs: `current()` stays set after the request (as `requestid.current()`) and assumes one request per thread at a time; `currentState()` is the thread's buffer. Tools: `tools/interop.zig` re-takes the OpenTelemetry Go oracle (`zig build interop-tracecontext [-- --check]`); the bench gains an OpenTelemetry Rust side. Tests: mutation run (73/76, 3 equivalent) and the tests it asked for. Grade 1.

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — Ported to Zig 0.17.0. `std.ascii.indexOfIgnoreCase` -> `findIgnoreCase` (bench tool). No behaviour change.

- **2026-10-11** — `tracestate` is parsed by the W3C member grammar (new `TraceState`: `parse`/`get`/`put`/`delete`/`write`/`members`; `isValidKey`, `isValidValue`, `max_members`, `max_key_len`, `max_value_len`): a list that fails the grammar or holds more than 32 members is dropped whole (was: carried if every byte was printable), optional whitespace and empty members are dropped, a key's later duplicates are dropped (the left one kept), the outgoing value is re-serialized `k=v,k=v`. New `Options.state_entry` (`StateEntry`): this service's own member, put in front (replacing its old one) and on new traces. Over 512 characters out: whole members left out, over-128-character ones first. Generated trace-/span-ids come from a process-wide atomic sequence with a per-process prefix (was: monotonic ns · thread-address nonce · per-thread counter, which could repeat across connection threads). W3C conformance: the 8 STRICT_LEVEL 2 vectors are asserted now (69 of 73); OpenTelemetry Go oracle divergences 27 → 12. Bench 0.55–0.67× otel (was 0.35–0.47×; the grammar check costs).

- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-tracecontext`, kept instrument kind 3): card Performance 0.35–0.47× OpenTelemetry Go TraceContext (net of the HTTP stack), measured on a quiet host. Tooling only, no code change.

- **2026-10-09** — tests: deterministic fuzz driver `TRACECONTEXT_FUZZ` over the existing harnesses.
- **2026-10-05** — **Fix:** `childOf` (and so the middleware's outgoing `traceparent`) keeps only the
  `sampled` flag; every other trace-flags bit was copied through, where W3C requires "all unparsed /
  unknown trace-flags" zeroed on outgoing requests (an incoming `…-ff` is still accepted and goes out
  `…-01`). Found by a new differential oracle against OpenTelemetry Go's propagator
  (`tools/go_oracle/`, `src/otel_oracle_test.zig`, 498 header sets). Anchor grade MIXED → EXTERNAL.

- **2026-10-04** — **Tests:** mutation run (22 schemata mutants, all killed after one new test
  covering the byte-35/52 delimiters, `Options.sampled = false` and DEL in a tracestate). No code
  change.

- **2026-09-30** — **NO CONSUMER-VISIBLE CHANGE:** the W3C suite's three
  `test_traceparent_version_0xcc` vectors run again. They had stayed marked out of scope
  ("forward-compat not implemented") after forward-compatible parsing landed on 2026-08-02, so
  the conformance test skipped exactly what the code does; now 61 executed, 12 excluded.
  `SPEC.md` no longer says higher versions are rejected.
- **2026-09-09** — Docs: `SPEC.md`'s pointer to the W3C corpus provenance was `../NOTICE`,
  which from the module directory resolves to `modules/NOTICE` — a path that has never existed.
  It means this module's own `NOTICE`. Found by the new link-resolution check in
  `zig build check-catalog`.
- **2026-09-09** — Licensing correction, no code change. `NOTICE` said the transcribed
  W3C conformance cases "add no condition beyond MIT's own"; the W3C 3-clause BSD
  License's third clause — no use of the W3C or contributor names to endorse derived
  products — has no MIT counterpart. Now stated. Also recorded: an earlier audit pass
  read the prose "copyright the W3C" as standing in for a missing copyright notice. There
  is no notice to stand in for — `w3c/trace-context`'s `LICENSE.md` is six lines naming
  two licences with no copyright line, and `test/test.py` carries none either (both
  re-verified 2026-09-09). The licensors are the repository's contributors, none of them
  named upstream, and this file now says exactly that instead of naming W3C as the
  copyright holder.
- **2026-09-09** — `src/w3c_vectors.zig`'s SPDX header pointed at `../../NOTICE`, which is
  `modules/NOTICE`, not this module's. Line 3 of the same file already had `../NOTICE` right.
  One character; it was the only SPDX header in the repository naming a foreign licence, so
  the one that most needed to resolve.

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

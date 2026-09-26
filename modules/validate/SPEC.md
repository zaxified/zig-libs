# validate — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Three tiers: a pure `Rule`-set validator core (no HTTP) → the typed style `parseInto(T, gpa, body)`
(comptime-reflected schema from struct `T`: optionals → nullable, defaults → not-required, int
bit-width → bounds, enums → `one_of`) plus a runtime-schema style `validateJson`/`validateValue` over
`std.json.Value` → `Body`/`TypedBody(T)`/`Query`/`PathParams` middleware for `router`. Never
fail-fast: every failure is aggregated into the `Report`; a wrong-typed field gets exactly one
`<kind>_type` error (no constraint noise) and other fields keep reporting (pydantic behavior). JSON
DoS caps (`Limits`): a fail-fast streaming token scan (`std.json.Scanner`) enforces `max_depth` (32),
`max_array_elements` (10,000), `max_object_members` (1,000) and `max_total_nodes` (1,000,000) *before*
the document is materialized into a `std.json.Value` tree — a cheap-to-send, expensive-to-parse
payload (deep nesting, huge arrays/objects) is rejected before it can blow up memory/CPU; a breach
yields a clean `too_deep`/`array_too_large`/`too_many_fields`/`too_many_nodes` error, never a panic or
an OOM. Allocation: one arena per validation run, owned by the returned `Report` (`deinit` frees
everything); codes are static strings, composed paths/messages live in the arena, simple paths borrow
`Rule.field` — the schema must outlive the Report. Middleware state is immutable after init, shared
across connection threads (reentrant); success data flows to handlers via a magic-tagged, stackable
`ctx.data` slot chain (`Query` + `Body` compose on one route). Format validators are pure: no
allocation, never panic on any byte sequence. Clean-room; design references pydantic v2 (error shape
+ code vocabulary), JSON Schema draft 2020-12 (keyword semantics + format vocabulary), and
go-playground/validator (struct-tag ergonomics) — behavior/format only, no source copied — see NOTICE.

**Streaming path** (`parseIntoLeaky`, `validateJsonStreaming`, 2026-09-22): the same rules without
the `std.json.Value` tree, for servers that decode into a fixed per-request buffer. The tree is 30–60×
the body (FBA minimum for `parseIntoLimited`: 16.5 KiB body → 955 KiB); the streaming path needs
~1.5× the body + ~2 KiB (same body → 25 KiB). One pass over `std.json.Scanner` tokens: a scalar
becomes a one-node `Value` and goes through the SAME `checkRule` (one implementation of the type gate,
constraints and messages); containers are walked in place (`required` settled at object end,
`min_len`/`max_len` at array end); a container whose rule has `custom` is materialized — that subtree
only — and checked by the tree code; error paths are stack-frame chains rendered only when an error
is recorded; both typed rule sets (derived + `T.validate_rules`) are walked together and
deduplicated as in the tree path. The walker is push-shaped (an explicit frame stack, fed one whole
token at a time), so for a typed body `std.json.parseFromTokenSourceLeaky(T)` pulls the tokens
through a tap that feeds each to the walker, which checks the structural limits on the way too:
**one tokenization** where there used to be three (limit pre-scan, walk, decode). A document the
decoder refuses, or the walker stops (duplicate key, a limit), is answered by the multi-pass path
instead -- pre-scan, walk, `parseFromSliceLeaky` -- so an invalid document gets exactly the report
and precedence it always had. Strings are borrowed from the body. Differences by design: errors in document order (tree: schema order), and a
different subset past `max_errors`. Equality of the error SET and of decoded values is pinned by a
differential fuzz target against the tree path.

## Threat model / out of scope
The JSON structural `Limits` are the security-relevant control here (JSON-DoS mitigation on untrusted
bodies); the byte cap (413) bounds size, the structural scan bounds shape. Explicitly out of scope:
`pattern` is literal/prefix/suffix/charset only — regex is not supported (a tracked future ADOPT
dependency); a top-level JSON array cannot be described (root must be an object, as with pydantic
models); `min`/`max` compare as f64, so 54+-bit integer bounds are not exact (`parseInto` surfaces an
out-of-range decode as a defensive root-level `invalid` error, never a crash); `uuid` format checks
shape only, not the RFC 4122 variant/version nibbles. Duplicate JSON object keys are refused at
every depth, known field or not (`json_invalid`, "DuplicateField") — `std.json`'s default, which
the streaming path reproduces by tracking the keys of every open object (this line said "last wins"
until 2026-09-22; it never did). Not a security boundary beyond the DoS caps — it does
not authenticate, authorize, or sanitize for injection (SQL/HTML); callers still own that.

## Verification
Every rule's code+path, cross-field aggregation, nested paths (`a.b`/`a[i]`), malformed/
empty/truncated JSON → clean `json_invalid` (never a panic), structural-limit rejections at each
bound, typed `parseInto` (derived bounds/enums/defaults/optionals, `validate_rules` merge, JSON-type-
error → pathed-error mapping), query coercion/percent-decoding/duplicate-key handling,
`router.Params` validation, byte-golden 400 error-body JSON; middleware tests over the socket-free
`http.Server.serveStream` (golden 400 + handler-not-invoked proof, valid POST → handler sees parsed
body, typed getter, 413 body cap, stacked Query+Body slot chain); an in-process `router`+`http.Server`
+`http.Client` loopback integration run (invalid POST → 400 with handler never invoked; valid POST →
decoded struct; bad query param → 400). Run: `zig build test-validate`.

## Backlog / deferred
Regex-backed `pattern` support is a tracked future ADOPT dependency (README TODO) — not implemented;
literal/prefix/suffix/charset matching is the v1 ceiling.

The middleware (`Body`/`TypedBody`/`Query`/`PathParams`) answers only in the plain
`{"errors":[…]}` shape with `application/json`. An opt-in to answer as RFC 9457
problem details (`writeErrorsProblem`, `application/problem+json`) is deferred until a
`router`-middleware consumer asks — the one consumer that wanted problem+json (qap,
2026-09-22) calls the core directly, not the middleware.

~~`parseIntoLeaky` scans the body twice~~ — DONE 2026-09-26 (qap M7.3), see *Streaming path*:
one tokenization for every document that decodes (`parseOnePass`), the multi-pass path for the
rest (`parseMultiPass`), both pinned against each other on the corpus and in the differential
fuzz target. Measured on a 33-byte two-field body (`perf stat instructions:u`, ReleaseFast,
stable to the instruction): 7,357 → 5,034 instructions per parse, against 2,221 for a bare
`parseFromSliceLeaky` -- the typed layer's cost down from +5.1 k to +2.8 k. It was three
tokenizations, not two: `jsonLimitError`'s pre-scan counted as well. History of the item:
`parseIntoLeaky` scanned the body twice: `streamValidate` walks it with a `std.json.Scanner`,
then `std.json.parseFromSliceLeaky` tokenizes it again to build `T`. Measured by qap
(2026-09-23, a 50-byte two-field body, `perf stat instructions:u`, stable to ±2 instr): the
typed layer costs **+7.6 k user instructions per request** over a hand-written
`parseFromSlice`, of which ~2.8 k are the second `Scanner.next` pass and ~0.85 k
`Stream.walkValue`. Wanted: one pass that checks the rules and fills `T` from the same
tokens (a validating `parseFromTokenSource`), same error codes and document order, still
body-sized memory. Differential test: one-pass vs today's two-pass on the existing corpus.
Scoped 2026-09-25 (qap M7.3, deferred by the consumer): the second tokenization is ~2.8 k of
the 7.6 k, so the ceiling is ~+12.6 % → ~+9 % per request. Recording the tokens in the walk and
replaying them into `parseFromTokenSourceLeaky` is simple but costs ~5× the body (a token per
~3 bytes at ~16 B each) -- past the body-sized budget a fixed per-request buffer has. The real
fix is a push-shaped walker (explicit frame stack instead of recursion) fed by a token-source
wrapper that `std.json`'s decoder pulls through, with the two-pass path kept as the fallback
for a body the decoder rejects mid-way (so the invalid path still reports every error).
~400-600 lines. Revisit when typed JSON dominates a profile.

## Status
`gap · any · util · reentrant` + deps: `router`, `http`, `netaddr` — canonical source is
`pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/json_schema_format_test.zig runs the official json-schema-org/JSON-Schema-Test-Suite optional/format files (src/testdata/json-schema-test-suite, 12 formats), which is where the isDuration bug was found; the whole 2020-12 CORE vocabulary in root.zig -- type/properties/items/required and the request-body integration -- is still graded only by this module's own tests

**How it got there.** The anchoring work landed. DONE 76f9d9c: format vocabulary only (rest out of scope), isDuration bug fixed

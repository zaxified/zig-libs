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

## Threat model / out of scope
The JSON structural `Limits` are the security-relevant control here (JSON-DoS mitigation on untrusted
bodies); the byte cap (413) bounds size, the structural scan bounds shape. Explicitly out of scope:
`pattern` is literal/prefix/suffix/charset only — regex is not supported (a tracked future ADOPT
dependency); a top-level JSON array cannot be described (root must be an object, as with pydantic
models); `min`/`max` compare as f64, so 54+-bit integer bounds are not exact (`parseInto` surfaces an
out-of-range decode as a defensive root-level `invalid` error, never a crash); `uuid` format checks
shape only, not the RFC 4122 variant/version nibbles; duplicate JSON object keys resolve per
`std.json` (last wins) before validation runs. Not a security boundary beyond the DoS caps — it does
not authenticate, authorize, or sanitize for injection (SQL/HTML); callers still own that.

## Verification
59 tests: every rule's code+path, cross-field aggregation, nested paths (`a.b`/`a[i]`), malformed/
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

## Status
`gap · any · util · reentrant` + deps: `router`, `http`, `netaddr` — canonical source is
`pub const meta` in src/root.zig.

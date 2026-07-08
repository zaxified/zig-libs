# SPEC — `validate`

**Purpose** — An internet-facing API must reject malformed input uniformly at
the edge, not with ad-hoc per-handler checks. `validate` is that layer: request
body/query/path-param validation with **aggregated**, machine-readable errors
(`{path, code, message}`), as a standalone core plus `router` middleware that
answers 400 without ever reaching the handler.

**Model after / Seed** — Clean-room; no seed project. Design references:
pydantic v2 (MIT — error shape + code vocabulary, `missing`/`int_type`/
`greater_than_equal`/`string_too_short`/`enum`/`format`/…), JSON Schema draft
2020-12 (spec — keyword semantics: `1.0` is a valid integer, inclusive
`minimum`/`maximum`, extra fields allowed, `enum`/`properties`/`items`
nesting, and the `format` vocabulary: `email`/`uri`/`uuid`/`ipv4`/`ipv6`/
`hostname`/`date`/`time`/`date_time`/`duration`/`json_pointer`), and
go-playground/validator (MIT — struct-tag ergonomics, mirrored as comptime
reflection). Behavior/format only, no source copied (NOTICE).

**Design & invariants**
- **Three tiers:** a pure `Rule`-set validator core (no HTTP) → the typed style
  `parseInto(T, gpa, body)` (comptime-reflected schema from struct `T`:
  optionals → nullable, defaults → not-required, int bit-width → bounds,
  enums → `one_of`) plus a runtime-schema style `validateJson`/`validateValue`
  over `std.json.Value` → `Body`/`TypedBody(T)`/`Query`/`PathParams`
  middleware for `router`.
- **Never fail-fast:** every failure is aggregated into the `Report`; a
  wrong-typed field gets exactly one `<kind>_type` error (no constraint noise)
  and other fields keep reporting (pydantic behavior).
- **JSON DoS caps (`Limits`):** a fail-fast streaming token scan
  (`std.json.Scanner`) enforces `max_depth` (32), `max_array_elements`
  (10,000), `max_object_members` (1,000) and `max_total_nodes` (1,000,000)
  *before* the document is materialized into a `std.json.Value` tree — a
  cheap-to-send, expensive-to-parse payload (deep nesting, huge arrays/objects)
  is rejected before it can blow up memory/CPU. A breach yields a clean
  `too_deep`/`array_too_large`/`too_many_fields`/`too_many_nodes` error, never
  a panic or an OOM; a syntax error is left to the real parser to report as
  `json_invalid`.
- **Allocation:** one arena per validation run, owned by the returned `Report`
  (`deinit` frees everything); codes are static strings, composed paths/
  messages live in the arena, simple paths borrow `Rule.field` — the schema
  must outlive the Report. Middleware state is immutable after init, shared
  across connection threads (reentrant); success data flows to handlers via a
  magic-tagged, stackable `ctx.data` slot chain (`Query` + `Body` compose on
  one route).
- **Format validators are pure:** no allocation, never panic on any byte
  sequence (empty, huge, non-UTF-8) — each is simply valid or not.

**Threat model / out of scope** — The JSON structural `Limits` are the
security-relevant control here (JSON-DoS mitigation on untrusted bodies); the
byte cap (413) bounds size, the structural scan bounds shape. Explicitly out
of scope: `pattern` is literal/prefix/suffix/charset only — **regex is not
supported** (a tracked future ADOPT dependency); a top-level JSON array cannot
be described (root must be an object, as with pydantic models); `min`/`max`
compare as f64, so 54+-bit integer bounds are not exact (parseInto surfaces an
out-of-range decode as a defensive root-level `invalid` error, never a crash);
`uuid` format checks shape only, not the RFC 4122 variant/version nibbles;
duplicate JSON object keys resolve per std.json (last wins) before validation
runs. Not a security boundary beyond the DoS caps — it does not authenticate,
authorize, or sanitize for injection (SQL/HTML); callers still own that.

**Verification** — `zig build test-validate`, 59 tests: every rule's
code+path, cross-field aggregation, nested paths (`a.b`/`a[i]`), malformed/
empty/truncated JSON → clean `json_invalid` (never a panic), structural-limit
rejections at each bound, typed `parseInto` (derived bounds/enums/defaults/
optionals, `validate_rules` merge, JSON-type-error → pathed-error mapping),
query coercion/percent-decoding/duplicate-key handling, `router.Params`
validation, byte-golden 400 error-body JSON; middleware tests over the
socket-free `http.Server.serveStream` (golden 400 + handler-not-invoked proof,
valid POST → handler sees parsed body, typed getter, 413 body cap, stacked
Query+Body slot chain); an in-process `router`+`http.Server`+`http.Client`
loopback integration run (invalid POST → 400 with handler never invoked; valid
POST → decoded struct; bad query param → 400).

**Status** — `gap · any · util · reentrant` · deps: `router`, `http`,
`netaddr`.

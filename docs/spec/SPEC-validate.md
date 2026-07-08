# SPEC — `validate`

Request input validation (body / query / path params) → structured 400 errors, as a `router`
middleware + a standalone validator. Web/API cluster (T5.9). `gap · any · util · reent`. Model
after: pydantic (error shape) + JSON Schema (draft 2020-12 keywords) + `go-playground/validator`.
Deps: `router`, `http` (uses `std.json`). New `build.zig` entry
`.{ .name = "validate", .deps = &.{ "router", "http" } }`.

## Why

An internet-facing API must reject malformed input uniformly at the edge with a clear, machine-
readable error, not ad-hoc per-handler checks. This is the validation layer.

## Scope

1. **Validators (the separable core):** a field-rule set — `required`, type (`string`/`int`/
   `float`/`bool`/`array`/`object`), `min`/`max` (numeric), `min_len`/`max_len` (string/array),
   `pattern` (simple — a literal/prefix/charset check, or note regex is out-of-scope/TODO since
   regex is an ADOPT dep not yet wired), `enum` (one-of), and a `custom` predicate fn. Validate a
   parsed value against a schema and **aggregate ALL errors** (not fail-fast) into a list of
   `{ path, code, message }`.
2. **Body (JSON):** parse the request body with `std.json` and validate. Support **two styles**,
   your call which to lead with (idiomatic Zig favors the first):
   - **Typed:** `parseInto(T, body)` — `std.json.parseFromSlice` into a caller struct `T`, then run
     field rules (a struct can declare its rules via a comptime decl or a parallel schema). Type
     mismatches from the JSON parse become validation errors, not crashes.
   - **Schema:** a runtime field-rule list validated against `std.json.Value`.
3. **Query + path params:** validate `http.Server.Request` query pairs and `router` path params
   against a rule set (all strings → coerce+check).
4. **Middleware:** `validate.body(schema)` / `.query(schema)` — runs before the handler; on failure
   short-circuit with **400** + a JSON error body (`{ "errors": [ { "path": …, "code": …, "message": … } ] }`,
   pydantic-ish); on success, make the validated/parsed data available to the handler (via `ctx.data`
   slot or a typed getter). Do NOT call `next` on failure.

## Public API sketch (final shape your call)

```zig
pub const Rule = struct { field: []const u8, kind: Kind, required: bool = false, ... };
pub const Error = struct { path: []const u8, code: []const u8, message: []const u8 };
pub const Report = struct { errors: []Error, pub fn ok(self) bool; };
pub fn validateValue(gpa, value: std.json.Value, schema: []const Rule) Report;
pub fn parseInto(comptime T: type, gpa, body: []const u8) ParseResult(T);   // typed style
pub fn bodyMiddleware(schema: []const Rule, opts) router.Middleware;         // 400 on failure
```

## Acceptance / verification

- **Offline unit tests:** each rule (required-missing, wrong-type, min/max, len, enum, pattern,
  custom) produces the right error `code`/`path`; **all errors aggregated** (multi-field bad input →
  multiple errors); valid input → `ok`; malformed JSON body → a clean validation error, never a
  panic; typed `parseInto` maps JSON type errors to validation errors; the 400 error-body JSON is
  well-formed (golden).
- **In-process integration (must NOT skip normally):** router+`http.Server`+`http.Client` — POST an
  invalid body to a validated route → 400 with the field-error JSON (handler not invoked); POST a
  valid body → handler runs and sees the parsed data; a bad query param → 400.
- `zig build test-validate` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Registered with `deps = &.{"router","http"}`.

## Notes for the implementer

- Use the **zig skill** (std.json Value + parseFromSlice, comptime reflection for the typed style).
  Reuse `router.Middleware {state,run}`, `Ctx`, `ctx.res`, `ctx.data`, and `http.Server.Request`
  query/body. Do NOT depend on `diagnostics` (not built) — emit the simple `Error` shape here.
- Aggregate errors (users hate fixing one at a time). Keep the validator core usable without HTTP.
- Regex `pattern` is out of scope (regex is a future ADOPT dep) — do literal/charset/length checks
  and note regex as TODO.
- SPDX header + a `Provenance:` line (clean-room; design refs pydantic MIT / JSON Schema /
  go-playground/validator MIT — behavior only).

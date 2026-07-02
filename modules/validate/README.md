# validate

Request input validation (body / query / path params) with **aggregated**,
machine-readable errors: a standalone validator core plus `router` middleware
that short-circuits invalid requests with a 400 and a
`{"errors":[{path,code,message},…]}` JSON body. T5.9 of the Web/API cluster.

Provenance: clean-room — no seed project and no third-party code. Design
references: pydantic v2 (MIT — the error shape `{path, code, message}` and
the error-code vocabulary; behavior only), JSON Schema draft 2020-12 (spec —
keyword semantics: `1.0` is an integer, inclusive `minimum`/`maximum`,
additional properties allowed, `enum`, `properties`/`items` nesting) and
go-playground/validator (MIT — struct-tag-style ergonomics, mirrored here as
comptime reflection; behavior only). No source copied.

- **Status:** `gap`.
- **Model after:** pydantic v2 + JSON Schema 2020-12 + go-playground/validator.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant — the
  validator core is pure; middleware state is immutable after init and every
  per-request allocation is request-scoped (one arena per validation run,
  owned by the returned `Report`).
- **Deps:** `router` (Middleware/Ctx/Next/ctx.data/Params), `http`
  (`Request` body/query, `ResponseWriter`), `std.json` (Value +
  parseFromSlice/parseFromValue).

## Usage

### Typed body (the idiomatic style)

```zig
const validate = @import("validate");

const CreateThing = struct {
    name: []const u8,          // required (no default), string
    qty: u8,                   // required, int, bounds 0…255 from the type
    price: ?f64 = null,        // optional + nullable
    color: enum { red, blue } = .red, // string with one_of from the enum

    // Extra constraints reflection cannot see:
    pub const validate_rules: []const validate.Rule = &.{
        .{ .field = "name", .kind = .string, .min_len = 1, .max_len = 64 },
    };
};

// As middleware (register on the group whose routes carry JSON bodies):
const Typed = validate.TypedBody(CreateThing);
const typed_mw: Typed = .{ .gpa = gpa };
const g = try r.group("/things");
try g.use(typed_mw.middleware());
try g.post("/create", handler);

fn handler(ctx: *router.Ctx) !void {
    const thing = Typed.get(ctx).?; // *const CreateThing, already validated
    ...
}

// Or standalone, no HTTP:
var result = try validate.parseInto(CreateThing, gpa, body_bytes);
defer result.deinit();
switch (result) {
    .ok => |parsed| use(parsed.value),
    .invalid => |report| for (report.errors) |e| log(e.path, e.code, e.message),
}
```

### Runtime schema (body, query, path params)

```zig
const schema = [_]validate.Rule{
    .{ .field = "name", .kind = .string, .required = true, .min_len = 1 },
    .{ .field = "qty", .kind = .int, .required = true, .min = 1, .max = 100 },
    .{ .field = "sort", .kind = .string, .one_of = &.{ "asc", "desc" } },
};

// Core (no HTTP):
var report = try validate.validateJson(gpa, body_bytes, &schema);
defer report.deinit();
if (!report.ok()) ...;                      // report.errors = []{path,code,message}
// Also: validateValue (an already-parsed std.json.Value),
//       validateQuery (raw query string), validateParams (router path params).

// Middleware:
const body_mw: validate.Body = .{ .gpa = gpa, .schema = &schema };
const query_mw: validate.Query = .{ .gpa = gpa, .schema = &query_schema };
const params_mw: validate.PathParams = .{ .gpa = gpa, .schema = &id_schema };
try g.use(body_mw.middleware());
// handler: validate.bodyValue(ctx).?.value  (std.json.Value)
//          validate.queryValues(ctx).?.get("q")  (decoded strings)
```

Middleware structs must outlive the router at a stable address
(`Middleware.state` points at them). On failure they answer **400** with
`Content-Type: application/json` and do **not** call `next`; an over-limit
body answers **413**. `Query` + `Body`/`TypedBody` stack on one route — the
`ctx.data` slots chain and both getters work.

## Rules

| Rule field | Applies to | Failure code |
|---|---|---|
| `required` | any | `missing` |
| `kind` | type gate | `string_type` `int_type` `float_type` `bool_type` `array_type` `object_type` |
| `allow_null` | any | (accepts explicit JSON `null`) |
| `min` / `max` (inclusive, f64) | int, float | `greater_than_equal` / `less_than_equal` |
| `min_len` / `max_len` | string (bytes) | `string_too_short` / `string_too_long` |
| `min_len` / `max_len` | array (items) | `too_short` / `too_long` |
| `one_of` | string | `enum` |
| `pattern` (literal/prefix/suffix/charset) | string | `string_pattern_mismatch` |
| `custom` predicate | any (after type gate) | rule-supplied (default `custom`) |
| `fields` | object (nested rules, paths `a.b`) | — |
| `items` | array (per-element rule, paths `a[i]`) | — |

Query/path coercion failures: `int_parsing` / `float_parsing` /
`bool_parsing`. Malformed JSON body: `json_invalid` at path `""`. Root not an
object: `object_type` at `""`. Codes are pydantic v2 vocabulary;
`array_type`/`object_type` are renamed from pydantic's `list_type`/
`dict_type` to match JSON, and the JSON-Schema `enum` keyword is spelled
`one_of` (`enum` is a Zig keyword).

## Semantics (pydantic / JSON Schema alignment)

- **All errors aggregated** — never fail-fast. A wrong-typed field gets
  exactly one `<kind>_type` error (no constraint noise), other fields keep
  reporting (pydantic behavior).
- **Type gate:** `1.0` is a valid integer (JSON Schema); an explicit `null`
  is *present* — it fails every typed kind unless `allow_null` (pydantic's
  `Optional` shape); extra/unknown fields are permitted.
- **Typed style** (`parseInto`/`rulesFor`): field with a default → not
  required (matches std.json's decoder, which errors on other missing
  fields); `?U` → `allow_null`; integer widths ≤ 53 bits get exact
  `min`/`max` from the type (wider unsigned keep `min = 0`; a value outside
  a 54+-bit range surfaces as a defensive root-level `invalid` error, never
  a crash); enums → `one_of` of the tag names; nested structs/slices recurse.
  Unknown fields are ignored on decode.
- **Query strings** are percent-decoded (`+` = space; invalid escapes pass
  through literally), first duplicate key wins (Go `net/url` semantics), and
  values are coerced per the rule kind before the shared checks run. Path
  params arrive raw (the router matches byte-for-byte, its documented
  policy). `array`/`object` kinds are not representable in a query string.
- **Bounds compare as f64** — exact for integers up to 2^53.

Known limits: `pattern` is literal/prefix/suffix/charset only — **regex is
out of scope** (a future ADOPT dependency; TODO in the module doc). A
top-level JSON array cannot be described by the field-rule schema (root must
be an object, as with pydantic models). `min`/`max` cannot express 54+-bit
integer bounds exactly. Duplicate JSON object keys resolve per std.json
(last wins) before validation sees the value.

## Verification

`zig build test-validate` — offline unit tests (every rule's code+path;
aggregation across fields; nesting paths `a.b` / `a[i]`; valid input → ok;
malformed/empty/truncated JSON → clean `json_invalid`, never a panic; typed
`parseInto` mapping JSON type errors to pathed validation errors, derived
bounds/enums/defaults/optionals, `validate_rules` merge; query
coercion/decoding/duplicates; `router.Params` validation; byte-golden 400
error-body JSON), middleware tests over the socket-free
`http.Server.serveStream` (golden 400 + handler-not-invoked proof; valid POST
→ handler reads the parsed body; typed getter; query/params middleware; 413
body cap; stacked Query+Body slot chain), plus an in-process integration run
(`router` + `http.Server` + `http.Client` over loopback: invalid POST → 400
field-error JSON with the handler never invoked; valid POST → handler sees
the decoded struct; bad query param → 400) that only skips when loopback
binding is unavailable.

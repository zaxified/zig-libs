# validate — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-22** — **`Limits.max_errors`: a caller can lower the error cap.** The
  report keeps at most `max_errors` errors (default and ceiling: the module's
  1000) and builds none past it; 0 counts as 1, so an invalid document is never
  reported valid. Honoured by `validateJsonLimited`, `parseIntoLimited` and the
  streaming path. Why: a caller decoding into a fixed buffer (qap's typed bodies)
  found that aggregating the errors of a body wrong everywhere costs more than
  decoding it — 1500 wrong items overflowed a 4 KiB buffer, so the answer read
  "too large" instead of "invalid". Test pins each path, the 0→1 rule and the
  ceiling.

- **2026-09-22** — **New streaming path: `parseIntoLeaky(T, arena, body, limits)` and
  `validateJsonStreaming(gpa, body, schema, limits)`** — the rules, codes and messages of
  `parseIntoLimited`/`validateJsonLimited` without building a `std.json.Value` tree. The tree
  costs 30–60× the body; the streaming path ~1.5× + ~2 KiB (smallest FixedBufferAllocator for a
  16.5 KiB body: 955 KiB → 25 KiB; 118 B body: 4.4 KiB → 704 B), so a server can decode typed
  bodies into a fixed per-request buffer. Scalars go through the same `checkRule`; containers are
  walked from the scanner's tokens; only a container with a `custom` rule is materialized. The
  decoded `T` is allocator-leaky and borrows unescaped strings from `body`. Errors come in document
  order; the error set equals the tree path's — pinned by a differential fuzz target and a
  hand-written edge set (escaped/duplicate/nested keys, malformed values inside a duplicate,
  number_string, fixed byte arrays). Also: `SPEC.md` claimed duplicate keys resolve "last wins";
  they are refused (`DuplicateField` → `json_invalid`), on both paths.

- **2026-09-22** — **FIX (memory safety): `parseInto`/`parseIntoLimited` freed
  the validation arena twice when the decode into `T` ran out of memory.** On the
  success path the error builder is aborted before `std.json.parseFromValue`
  runs, but its `errdefer b.abort()` was still armed, so an `OutOfMemory` from the
  decode deinitialized the same arena again — a double free on a heap allocator
  (heap corruption in ReleaseFast), an assertion on a `FixedBufferAllocator`.
  Reachable by any caller whose allocator can fail (a bounded arena, a request
  budget). Found by a sizing probe on a `FixedBufferAllocator`. New test sweeps
  every allocation failure point of `parseIntoLimited`, `validateJsonLimited` and
  `validateQuery` with `checkAllAllocationFailures` (no leak, no double free);
  red on the old code.

- **2026-09-22** — **Errors as RFC 9457 problem details, and `validateParams`
  over any lookup.** New `Report.writeProblem(w, http.problem.Problem)` and the
  standalone `writeErrorsProblem(errors, problem, w)`: an
  `application/problem+json` body whose `errors` extension member is the same
  `[{path,code,message},…]` list `writeJson` writes. `validateParams` now takes
  `params: anytype` — anything with `get(name: []const u8) ?[]const u8`, by value
  or pointer — instead of only `*const router.Params`, so a server whose params
  type is its own can use it; existing `&router.Params` callers compile
  unchanged, and a type without such a `get` is a compile error that says so.
  The middleware still answers 400 with `application/json` (see SPEC backlog).

- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/json_schema_format_test.zig` and `src/json_schema_format_vectors.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-09-07** — **Test-only: neither fuzz target had a corpus, so each ran
  exactly ONE input for ever, and `fuzzValidateFormat`'s was `.email` with the
  empty string.** Outside `--fuzz` the runner feeds `options.corpus` plus one
  round of `in = ""`, and every `Smith` draw on an exhausted input returns its
  minimum. So `fuzzValidateJson`'s opening `smith.value(bool)` was false, every
  per-field `smith.value(bool)` was false too, and the body it assembled was
  `"{}"` — the type gate, the format and pattern checks, the min_len/max_len
  bounds and the nested object/array walk, which the harness's own comment
  lists as the whole reason the shape generator exists, had never run.
  `fuzzValidateFormat` was worse: `smith.value(Format)` returned the first enum
  value on every input, so **eleven of the twelve formats had never been called
  at all**. Both now draw once with `smith.slice` and read their choices from
  the drawn octets through `testkit.fuzz.Cursor`, with seeds whose first octet
  selects "the rest is the body/string verbatim" or "the rest is a script".
  Measured 2026-09-07: **JSON target 1 body and 2 violations before; 17 bodies
  over 692 octets, 2 of them valid, 23 violations after. Format target 1 format
  and 0 non-empty strings before; all 12 formats, 21 non-empty strings and 12
  accepted after.** ⭐ The JSON guard pins the violation COUNT rather than
  acceptance, because acceptance is wrong at both ends here — `{}` is refused
  for two missing required fields, and a fully valid body is refused by nothing,
  so a corpus stuck at either extreme reads as a clean pass.

- **2026-09-02** — **Audit (drift campaign): 4 MEDIUM, 3 LOW.** No memory-safety defect and no
  mode difference anywhere; every finding is about a rule that did not do what it says.
  **MEDIUM, BEHAVIOURAL — `kind = .any` no longer voids every constraint.** `.any` is the
  DEFAULT `kind`, and it used to skip the whole constraint switch — so one omitted
  `.kind = .string` turned a rule carrying `required`, `format`, `min_len`, `max_len`, `one_of`
  and `pattern` into a silent no-op (`ok() == true` on input violating all six), with no comptime
  or runtime signal. It now means "any TYPE is acceptable": whatever type arrives is held to the
  constraints the rule states. A rule with no constraints is unaffected, which is what `.any` was
  for. **A validator that fails open by default is worse than no validator.**
  **MEDIUM — new `min_bytes`/`max_bytes`, and the derived `[N]u8` rule uses them.** When lengths
  became code points, `rulesFor(struct { fixed: [16]u8 })` kept emitting `min_len = max_len = 16`
  — 16 CHARACTERS against a decoder that fills 16 BYTES. `"éééééééé"` (16 bytes, 8 code points)
  decodes perfectly and was REJECTED; a 16-code-point/17-byte string passed the rule and then
  failed inside `parseFromValue` as an unpathed root `invalid`. `rulesFor` is `pub`, so the
  false-yes is reachable without the decode.
  **MEDIUM — `max_errors` now bounds the WORK, not just the list.** The cap was checked inside
  `append`, after `appendf` had already formatted the message, and `indexPath` allocated a path
  for every array element regardless of outcome. Measured: a 996 KiB body of 340 000 nodes — all
  of it inside the DEFAULT `Limits` — built 339 000 messages nobody could read and held an
  **18 802 KiB** report arena for the 1000 errors it kept. Pinned by a counting allocator with a
  4 MiB ceiling; the old code overshoots it by 4.7×.
  **MEDIUM — three of the four `Limits` defaults SPEC names as the security control had nothing
  pinning them.** Raising `max_array_elements` 10 000→1e8, `max_object_members` 1 000→1e8 or
  `max_total_nodes` 1e6→1e11 each left the suite fully green; the one test that claimed to cover
  this exercised `max_depth` alone. The defaults worked — nothing would have noticed them
  stopping.
  **LOW — docs:** `README` and `Rule`'s struct doc still said string lengths are BYTES, which is
  what made the `[N]u8` defect easy to miss; the README's RFC list now names the one place
  `date`/`time`/`date_time` are laxer than RFC 3339 (the optional offset).
  **LOW — `isEmail`'s documented 254-byte ceiling** and **the offset-optional date-time profile**
  are pinned. Removing the email cap left the suite green while 255–318-byte addresses became
  acceptable; the date-time choice had no corpus case at all in either direction.
  Ledger: `~/CML/20260931-zig-libs-audit/validate.md`.

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

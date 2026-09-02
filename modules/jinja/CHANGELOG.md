# jinja — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-02** — Drift re-audit (W2, window `d163578..HEAD`). Thirteen findings, all fixed:

  - **CRITICAL, escaping:** `xmlattr` did not validate attribute *names*. `escapeTo` is
    markupsafe's `& < > " '` set, so a space, tab, `/` or `=` in a dict key passed through
    untouched and the result was marked safe — `{{ d|xmlattr }}` with the key
    `a onmouseover=alert(1) b` rendered a live event handler out of an autoescaped template
    with no `|safe` anywhere, from context data alone. The reference refuses such a key
    (`ValueError`, added in 3.1.3/3.1.4); this module never got that half.
  - **CRITICAL, memory safety:** `minInt(i64) // -1`, `% -1` and `is divisibleby(-1)` trapped —
    `@divTrunc`/`@rem`/`@mod` are undefined there, which is a panic in Debug and a **SIGFPE**
    in ReleaseFast, reachable from ordinary context data. `pyFloorDiv`/`pyMod` return an error
    union now; their siblings `.add`/`.sub`/`.mul` always did.
  - **CRITICAL, memory safety:** `max_nesting_depth` bounds the **syntax** tree and says nothing
    about the depth of a `Value`. `strTo`/`reprTo`, `tojson`'s `jsonWrite` and `fromJson` walked
    that depth unbounded: 70 000 levels built by a 103-byte template was a **SIGSEGV** in
    ReleaseFast, and so was 200 000 levels of nested JSON handed in as context.
    `value.max_value_depth` (256) bounds all four as `error.OutOfRange`.
  - **New option `max_render_bytes` (256 MiB), new error `RenderBudgetExceeded`.** The depth caps
    bound depth; `value.max_alloc`/`max_items` bound one operation. Nothing bounded a render's
    total work, and the arena is not reclaimed until the render ends. A macro fan-out at depth 22
    — a third of `max_call_depth` — took 3.8 GB and emitted **zero bytes**, so `max_output_bytes`
    never saw one; `{{ ('a' * 30000)|replace('', 'b' * 30000) }}` multiplied two 64 MiB caps
    together from a 53-byte template. Kept distinct from `OutOfMemory`: the machine has memory,
    the render asked for more than it is allowed.
  - **Breaking (behaviour):** an undefined value passed as a *numeric argument* is
    `error.UndefinedValue`, not the argument's default. `{{ x|int }}` answered `0` and
    `{{ 'a'|center(x) }}` padded to 80 columns under the module's own `.strict` default — the
    reference raises for both under `Undefined` and `StrictUndefined` alike, and a silent `0`
    where an MTU belonged is exactly what this module's undefined policy exists to prevent.
  - `truncate` kept the whole prefix when it contains no space, as `rsplit(" ", 1)[0]` does.
    It used to return only the ellipsis — every URL, hostname, interface name and base64 string
    truncated to nothing.
  - `|int(default, 0)` reads the literal's own prefix: the hand-rolled strip ran before
    `parseInt`, so base 0 saw a bare digit string (`'0b101'|int(0,0)` answered 101, not 5).
  - `wordcount` counts runs of `\w` rather than whitespace-separated tokens; `striptags` treats
    an unterminated `<` as text instead of dropping the rest of the string; `urlencode` uses the
    query-string form for a mapping (a space is `+`) and accepts an iterable of pairs.
    All four verified against live Jinja2 3.1.6 and added to the corpus, so the live reference
    judges them from here on.
  - The loader distinguishes `ENOTDIR` from a regular-file path component (genuine absence,
    ignorable) from `ENOTDIR` from a refused symlinked directory (an escape attempt, `LoaderFailed`).
    The 2026-08 F13 fix had conflated them, so `{% include 'regular/x' ignore missing %}` failed
    the render.
  - Fuzzing: the `xmlattr` autoescape site was written `{{ e|xmlattr if false else … }}`, so the
    filter was never evaluated; the fixture never put drawn bytes in a map **key**; and the
    oracle was `indexOfAny(out, "<>")`, while an attribute-context injection contains neither
    character. A dedicated target now draws the key and re-parses the result as
    `<img( name="value")*>`, and that oracle has a test of its own.
  - Docs: SPEC's resource-exhaustion and recursion sections both claimed bounds that did not
    hold, and README claimed filter resolution "can never surface halfway through a render",
    which is false for a filter named by a string argument to `map`/`select`/…. Five divergences
    (D18–D22) that were in neither the corpus nor the table are now in the table.

- **2026-08-06** — Security audit: an autoescape bypass via the `replace` filter could
  inject unescaped markup into rendered output; fixed, along with an integer-overflow
  allocation guard, an unbounded expression-nesting DoS, and 9 further findings (2
  accepted as measured non-issues, not defects).
- **2026-07-30** — New module: Jinja2-compatible template engine — `{{ … }}`, `{# … #}`,
  `{% if/elif/else %}`, `{% for %}` with the full `loop` object.

# jinja — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **All five fuzz harnesses were replaying one fixed input — the empty
  template, the empty context datum, one table entry of 32 — and now each has a corpus
  with a measured reach guard.** Every target opened with a ranged draw
  (`smith.indexWithHash(buf.len, 0)`, `smith.index(num_sites.len)`,
  `smith.index(escape_sites.len)`), and a ranged draw reads eight input octets as a
  little-endian u64 and returns the range MINIMUM unless that whole word already lies
  inside the range. Outside `--fuzz` the lane replays a target's corpus and then one round
  of `in = ""`; none of the five had a corpus. So: `fuzzCompileAndRender` and
  `fuzzWhitespaceOptions` compiled the EMPTY template, every time, for their whole life —
  and the empty template compiles and renders without error, so nothing looked wrong;
  `fuzzCompileAndRender`'s context datum `s` (the attacker-*data* path F12 added) was
  empty on every run as well; `fuzzNumericArgs` rendered `num_sites[0]` with the number 0
  as an integer literal — 1 of its 96 (site × spelling) combinations, because the two
  spelling knobs were drawn AFTER the number and a draw made on exhausted input is its own
  minimum for ever; `fuzzAutoescapeInvariant` rendered `escape_sites[0]` with `e` empty,
  so its oracle had nothing to judge; and `fuzzXmlattrInvariant` rendered one attribute
  whose NAME and value were both `""` — the name being the half the F-D3 CRITICAL lived
  in. Each now draws bytes first with `Smith.slice`, the two table indices are not drawn
  at all (every site runs on every input, which is what a table of places is for), the
  numeric spellings are looped rather than drawn, and the number itself is read out of the
  seed through `testkit.fuzz.Cursor`. Corpora: 36 template/context pairs quoted from
  `testdata/golden.json` (the reference replay's own captured Jinja2 corpus), 17
  whitespace-control templates, 17 numbers a narrowing cast can go wrong on, 21 hostile
  context strings, 20 attribute key/value pairs including the audit's own
  `a onmouseover=alert(1) b`. Measured before → after: templates 0→36 non-empty and
  0→1004463 output octets; context data 0→10; whitespace 0→17 and 0→1002072 octets;
  numeric 1→1632 site renders; autoescape 1→672 site renders and 0→1978 escaped markup
  octets; xmlattr keys 0→19 non-empty, values 0→19, 0→179 attribute octets. ⚠ The
  autoescape and xmlattr **oracles are now asserted in the ordinary lane too**: a
  `std.testing.fuzz` body never runs without `--fuzz`, so until now the only check on
  either invariant was a sweep nobody runs. Both hold across the whole corpus. The `F12`
  regression test was rewritten for the new draw — its length header is a little-endian
  u32 now, not a u64 — and it additionally asserts the last drawn octet arrived, not just
  that the length did.

- **2026-09-06** — The Python oracle leaves the module. `src/reference_test.zig`
  `@embedFile`d the Jinja2 driver into module source and spawned `python3` from
  inside `zig build test-jinja`, so every consumer carried foreign source and the
  live half of the anchor **skipped** — asserting nothing — on any host without
  jinja2, CI's `continue-on-error` peer install included.

  - the corpus and the driver are now `tools/corpus.zig` and `tools/reference.py`,
    run only by the new `tools/interop.zig` program (`zig build interop-jinja`,
    `-- --capture`), which `zig build check-interop` compiles and never runs;
  - `src/testdata/golden.json` becomes a self-describing transcript: all **351**
    cases, each carrying the inputs the reference was given (template, loader
    templates, JSON context, and the autoescape / undefined / whitespace knobs)
    next to the bytes it returned — where before it held outputs alone and leaned
    on `src/corpus.zig` for the inputs;
  - its header now records the Jinja2 **and MarkupSafe** versions, the Python
    version, the capture date and command, and a `determinism` block: the pinned
    child environment (`PYTHONHASHSEED=0`, `LC_ALL=C`, `LANG=C`, `TZ=UTC`), the
    float repr style, the delimiters, the loaded extensions (none) and Jinja's
    whole `policies` table;
  - `src/golden_test.zig` becomes `src/reference_replay_test.zig` and replays it
    with **no `python3` anywhere**. Coverage is unchanged at 351 of 351 cases
    compared byte for byte; `test-jinja` goes from 74 tests with 3 skipped on a
    Python-less host to **72 tests with 1 skipped** — and that one is the
    env-gated benchmark, not conformance.
  - the replay refuses to shrink: it fails below 351 cases, requires unique
    names, requires every entry to carry its inputs, requires the corner counts
    the corpus exists for (≥50 with a loader, ≥30 the reference refuses, ≥35
    autoescaped), and requires the provenance header.

  `src/conform.zig` now decodes a case from the transcript instead of reading a
  Zig table; no published API changed.

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

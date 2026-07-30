# jinja — design & threat model

What this module is and how to use it: see `README.md`. This file answers why it
is built the way it is, where it deliberately differs from the reference, and
what it is verified against.

## 1. Shape

```text
source bytes
   │  lexer.zig    text / {{…}} / {%…%} chunks, tag interiors tokenized,
   │               whitespace control applied, {% raw %} resolved
   ▼
 pieces
   │  parser.zig   recursive descent mirroring the reference's layering;
   │               filter + test NAMES resolved here against the environment
   ▼
 ast.Node tree ── owned by an arena inside `Template`, immutable
   │  render.zig   scope frames, evaluation, output; filters.zig supplies
   │               the builtin library and value methods
   ▼
 bytes
```

Three properties fall out of that staging and are worth stating:

**Whitespace control is a pass over a chunk list, not a rule inside the
parser.** `{%-`, `-%}`, `trim_blocks` and `lstrip_blocks` all mean "edit the
text on one side of this tag". Recording a mark per tag and applying the edits
afterwards makes the interaction between the four mechanisms (and the `+`
opt-out) a table of slice edits, which is why the corpus can afford to test
every combination of them.

**Name resolution happens at compile time.** `parser.Registry` asks the
environment whether a filter/test name exists while parsing. The reference does
the same thing (`TemplateAssertionError` at compile time), and the reason is
identical: a template that references a filter you do not have must fail before
it is used, not halfway through emitting a device configuration.

**A compiled template is immutable and shareable.** It owns an arena holding a
copy of the source and the tree; nothing is mutated at render time, and each
render allocates its own scratch arena. That is what makes `Template` safe to
render from several threads.

## 2. The value model — why a fourth `Value` type, and why no `yaml` dependency

The obvious options were `std.json.Value`, `yaml.Value` (ordered pairs), or an
interface with adapters. The decision is: **the render-time value is this
module's own type, and ingress is a conversion** (`valueFrom` for Zig data,
`valueFromJson` for `std.json.Value`, a documented ~20-line function for
`yaml.Value`). `deps` stays empty.

Three things drove it.

**Neither candidate can express what Jinja requires at render time.** Jinja has
two semantic distinctions that decide behaviour, and neither type has them:

- *undefined vs null*. `{{ x }}` for a missing `x` and for `x = null` are
  different: one is a policy decision (empty? error?), the other renders
  `None`. Collapse them and `{% if x is none %}` and `{% if x is defined %}`
  become the same question. Both `std.json.Value` and `yaml.Value` have exactly
  one "absent" state.
- *string vs markup*. `|safe` must be representable **in a value**, because it
  travels: `('<b>'|safe) ~ '<i>'` escapes only the second half. A plain string
  type cannot carry that bit, and without it autoescaping is either wrong or
  absent.

Values also come into existence during a render that were in no input at all —
`loop.index`, `range(5)`, the result of `|sort`, a `namespace()` — so a render
value type exists no matter which ingress type is chosen. The only real question
was whether the *context* should also be one of the candidates.

**The ordered-vs-unordered argument does not discriminate.** This was the reason
to prefer `yaml.Value`, and checking it dissolved it: `std.json.Value.object` is
a `StringArrayHashMap`, i.e. already insertion-ordered. Both candidates preserve
order, so order cannot pick between them. Our `Map` is an ordered pair slice for
the same reason, and because it can then hold non-string and duplicate keys the
way both candidates can.

**A dependency would be paid by every consumer, to no one's benefit.** With the
render value already ours, a `yaml` dependency would buy exactly one conversion
function — one that a caller can write in twenty lines, that must be written
anyway for any *other* source (a database row, an env-var map, a CLI flag set),
and that forces everyone who templates a JSON or Zig-struct context to build the
YAML scanner. `std.json` is adapted in-tree only because it costs nothing: it is
std.

The primary ergonomic path is neither adapter but `valueFrom`, comptime
reflection over ordinary Zig data — structs become ordered maps in field order,
`[]const u8` a string, slices lists. Most callers never construct a `Value`
literal at all.

A lazy vtable (`External`) over caller memory was considered and rejected:
adapters would be resolved on demand instead of converted up front, but every
operation in the evaluator (attribute, item, iterate, length, truth, compare,
str) would grow a dynamic-dispatch path, and the evaluator is where correctness
lives. Contexts for configuration templating are small; conversion is an arena
memcpy. If a caller ever appears with a context too large to convert, the
conversion functions are the seam to make lazy, and no template semantics change.

## 3. Scoping

`{% for %}` and `{% with %}` push a frame; `{% if %}` does not; `{% set %}`
always writes to the innermost frame; lookup walks outward and then falls
through to the context. That reproduces the reference exactly, including the
consequence everybody trips over once:

```jinja
{% set total = 0 %}
{% for x in [1,2,3] %}{% set total = total + x %}{% endfor %}
{{ total }}   {# 0, not 6 — the loop's `total` died with the loop #}
```

One frame is pushed per loop, not per iteration, so a `{% set %}` in iteration
one *is* visible in iteration two. `namespace()` is the escape hatch and is
implemented as the model's only mutable value: a pointer to a pair list, with
`{% set ns.attr = … %}` as an attribute assignment target in the parser.

`loop` is a pointer to a live `Loop` record rather than a snapshot map, so
`{% set outer = loop %}` in an outer loop keeps tracking that loop — the same
aliasing the reference has, and the only way to read an outer loop's index from
an inner one.

## 4. Undefined — divergence D1, stated once here

The default is `.strict`; the reference's default is lenient. This is the
module's single default-path behavioural divergence and it is a deliberate
inversion, not an omission.

The reasoning is the workload. This engine exists to render configuration. Under
the lenient policy a typo'd variable renders as the empty string, and the output
is a syntactically valid configuration file with a missing address, a missing
peer, or an empty ACL — which is deployed, and then diagnosed hours later. A
failed render is a worse-looking failure and a much cheaper one. HTML, where
lenient makes sense (a missing sidebar is a missing sidebar), is not what this
is for, and no loader here guesses otherwise.

`.lenient` reproduces the reference precisely, including its own asymmetries,
which were read off the live oracle rather than assumed:

| operation on undefined | `.lenient` (= reference default) | `.strict` |
|---|---|---|
| `{{ x }}` | `""` | error |
| `{% if x %}` | falsey | error |
| `{% for i in x %}` | **empty, not an error** | error |
| `x\|list` | `[]` | error |
| `x.attr`, `x[0]` | error | error |
| `x + 1` | error | error |
| `x is defined` / `x is undefined` | works | works |
| `x\|default(v)` | `v` | `v` |

The `for` row is the one that would have been guessed wrong: the reference's
`Undefined` raises on attribute access but iterates as empty. The corpus pins
both.

## 5. Autoescaping

Off unless asked. With it on, output is escaped with markupsafe's exact set —
`&` `<` `>` and the **numeric** quote entities `&#34;` / `&#39;`, not `&quot;` —
and the safe bit propagates the way `Markup` does: `~` and `+` escape a
non-markup operand and yield markup, `|join` escapes items and the separator,
case-changing filters preserve markup, `|escape` on markup is a no-op while
`|forceescape` is not, and a `{% set %}`/`{% filter %}` block captures markup.
Every one of those is a corpus case, because each is a plausible place to get
double-escaping or, worse, no escaping.

## 6. Divergences from Python Jinja2 3.1.6

Everything not covered by a corpus case is here. Nothing in this table is a
relaxed test; each is either a compile error (so a caller meets it immediately)
or a documented, tested behaviour.

| # | Divergence | Kind |
|---|---|---|
| D1 | Default `undefined_policy` is `.strict` (see §4) | default, opt-out |
| D2 | Template inheritance/reuse — `extends`, `block`, `include`, `import`, `from`, `macro`, `call`, and i18n `trans` — is not implemented | **compile error naming the tag** |
| D3 | Integers are `i64`; Python's are arbitrary precision. Overflow is `error.OutOfRange` where Python grows the number | runtime error |
| D4 | `upper`/`lower`/`capitalize`/`title` and the `is upper`/`is lower` tests are ASCII-only; Python applies Unicode case mapping. Length, indexing, slicing and iteration of strings *are* codepoint-correct | silent, ASCII-identical |
| D5 | `map`/`select`/`reject`/`selectattr`/`rejectattr`/`items`/`dictsort`/`batch`/`slice` return lists, not generators, so rendering one directly prints `[…]` where the reference prints `<generator object …>` | silent, strictly more useful |
| D6 | Filters absent: `attr`, `filesizeformat`, `format`, `groupby`, `pprint`, `random`, `urlize`, `wordwrap` | **compile error** |
| D7 | Tests absent: `callable`, `sameas`, `filter`, `test`, and the symbolic aliases (`is ==`, `is >`, …) — the named forms `eq`, `gt`, … are present | **compile error** |
| D8 | Globals absent: `lipsum`, `cycler`, `joiner` | **compile error** |
| D9 | `{% for … recursive %}`, `*args`/`**kwargs` in calls, line statements/comments, custom delimiters, and calling anything other than the built-in globals | **compile error** |
| D10 | `{% do %}` and `{% with %}` need no extension to be enabled | superset |
| D11 | String methods are a documented subset (README); an unknown one is a render error naming the type and method | runtime error |
| D12 | `round(x, p)` falls back to scaled arithmetic when the exact integer form would exceed `u128` (roughly `|p| > 22`) | silent, beyond f64 precision |
| D13 | `max_output_bytes` (64 MiB) and a 4 Mi-element cap on `range()`/`'x' * n` have no reference equivalent | extra refusal |
| D14 | No loader and no file system: templates are strings | API |

Why `attr` was dropped rather than implemented (D6): the reference's `attr`
filter is `getattr` *without* the `getitem` fallback, so applied to a mapping —
which is what every context value here is — it returns undefined, always. A
filter that can only ever produce undefined is a trap; a compile error saying it
does not exist is better than a faithful no-op. `map(attribute=…)` and
`selectattr` keep working on mapping keys, because those use the fallback path in
the reference too.

## 7. Verification

The anchor is **Python Jinja2 3.1.6**, the reference implementation, and the
comparison is byte-for-byte: `src/corpus.zig` holds 209 cases (template +
JSON context + syntax options), and both oracles render exactly that table.

**Live peer** (`reference_test.zig`). `testdata/reference.py` renders the whole
corpus in a `python3` subprocess and returns JSON; every case is compared
against ours. This is the only oracle that has never seen this code, and it is
what catches the defect class self-written expectations cannot: a *consistent*
misreading. Implement `%` with C truncation instead of Python flooring and every
hand-written test in this repository still passes while every template ported
from a real Jinja deployment renders a different configuration.

**Committed golden** (`golden_test.zig` + `testdata/golden.json`). The same
driver's output, committed, with the reference's version recorded in the file.
It is checked in both directions: a corpus case with no golden entry fails, and
a golden entry with no corpus case fails.

Neither subsumes the other, which is why both are kept. The live peer catches
drift that a committed expectation would happily agree with; the golden keeps
the assertion alive on a host with no Python at all, and pins the *specific*
bytes that a tolerant peer, a newer peer, or an absent peer would leave
unasserted. A regression on a Python-less CI runner is exactly the case where
one oracle without the other proves nothing.

**Regenerating the golden** (required after any corpus change):

```sh
ZIG_LIBS_JINJA_REGEN=$PWD/modules/jinja/src/testdata/golden.json \
  zig build test-jinja
```

The hook lives inside the live test, so the golden can only ever be produced by
the same procedure the live comparison uses.

**Load-bearing check.** The oracle was verified to be load-bearing by mutation:
changing `pyMod` from Python's floored remainder to `@rem` (C truncation) — a
change no unit test in this module notices — turns `mod_negatives` red in both
the live and the golden test (`1|1|-1|-1` vs `1|-1|1|-1`). That mutation was
reverted.

**What the corpus is weighted towards.** Not the easy paths: whitespace-control
combinations including `+` and the option interactions, `loop` inside nested
loops, `{% set %}` scoping inside a loop body versus `namespace()`, floor
division and modulo on negative operands in both int and float, banker's
rounding at ties and at values like `2.675` that are not the decimal they look
like, filter argument evaluation, autoescape interacting with `|safe`/`|escape`/
`~`/`|join`, `repr` of every value kind, and the cases where the reference
*errors* (each marked, and required to fail on our side too).

**Fuzzing** (`fuzz_test.zig`): arbitrary bytes as template source, with and
without the whitespace-rewriting options, must never trip a safety check. Any
`error` is a fine outcome. Per CONVENTIONS §7.1, that evidence is about a Debug
or ReleaseSafe build.

**Unit tests** (`engine_test.zig`) cover what the reference has no equivalent
of: compile-time name resolution, diagnostics and line numbers, custom
filters/tests, `valueFrom` reflection, template reuse, `renderTo`, and the
output/`range()` ceilings.

## 8. Threat model

Two untrusted inputs, treated differently.

**The context is data.** It is never parsed as template syntax — `{{` in a
rendered value is bytes. There is no `eval`-equivalent: `{{ x() }}` reaches only
the three built-in globals, and anything else is `error.NotCallable` at render
time.

**The template is code.** A template can read anything in the context it is
given and can loop; it cannot open files (no loader), reach the environment, or
call arbitrary functions. Against resource exhaustion, `max_output_bytes` bounds
output, `value.max_items` bounds `range()` and list repetition, and
`value.max_alloc` bounds string repetition — so `{{ 'x' * 10**9 }}` and
`{% for i in range(10**9) %}` fail rather than being attempted. Recursion in the
evaluator follows template nesting depth, which is bounded by the source's
bracket nesting; the fuzz harnesses exercise that path.

Escaping is a policy the caller sets, not a guess: with `autoescape = false` the
module never escapes anything, and with it on the safe bit is the only way to
opt a value out. Because `|safe` is representable in a value, a caller can mark
trusted fragments in the *context* rather than in the template.

## 9. Backlog

- **Part 2: inheritance and reuse** — `{% extends %}`, `{% block %}` (with
  `super()` and `scoped`), `{% include %}` (with `ignore missing` / `without
  context`), `{% import %}` / `{% from %}`, `{% macro %}` + `{% call %}` +
  `caller()`, and the `Loader` abstraction they all need. The parser already
  reserves every one of those tag names with a "not implemented" error, so
  adding them cannot silently change the meaning of an existing template.
- `{% for … recursive %}` and `loop()` — small once macros exist, since both
  need a callable body.
- The eight absent filters (D6). `groupby` and `pprint` need a decision about
  what to render for a namedtuple and for Python's pretty-printer layout before
  they can be byte-exact; `random` needs a seed in the environment to be
  testable at all; `wordwrap` needs `textwrap`'s exact algorithm.
- Line statements and configurable delimiters — cheap in the lexer, wanted only
  if a real consumer asks.
- A lazy context adapter (§2), if a context ever appears that is too large to
  convert eagerly.

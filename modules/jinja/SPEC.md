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
   │               filter + test NAMES resolved here against the environment;
   │               blocks collected into a per-template table
   ▼
 ast.Parsed ───── nodes + block table + extends; arena-owned, immutable
   │  render.zig   scope frames, inheritance chain, macros, evaluation, output
   │               loader.zig supplies bytes for named templates
   │               filters.zig supplies the builtin library and value methods
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
render from several threads — and it is why the loader is wired the way §9
describes rather than as an environment-level template cache.

**Where `{% for … recursive %}` belongs.** The brief asked for a decision, and
the answer is that it is *not* composition: it needs no second template and
nothing from a loader. It belongs with Part 1's `{% for %}`, and it landed here
only because it shares machinery with macros — `loop()` re-enters the loop body
the way a macro call re-enters a macro body, against the same `max_call_depth`,
and building that twice would have been the wrong shape.

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

Frames are held **by pointer** (`[]const *Frame`), never by value. That is not
tidiness: a macro closes over the frames it was defined in, and a hash map
copied by value would be left pointing at freed storage the moment the original
grew. Holding pointers is also what makes a macro see a `{% set %}` written
*after* it — which is the reference's behaviour, verified.

Composition adds three scope rules, each read off the reference rather than
reasoned about:

- **A block sees only template-level names.** Rendering a non-`scoped` block
  swaps the stack for `[template frame, fresh frame]`, which is why a block
  inside a `{% for %}` cannot read the loop variable. `scoped` pushes onto the
  live stack instead.
- **An `{% include %}` with context sees the whole current stack** (loop
  variables included) plus a fresh frame of its own, so its `{% set %}`s do not
  leak back. Without context it starts from an empty stack *and* an empty
  render context — the reference hides the context too, not just the locals.
- **A macro carries its frames, not its caller's.** `{% import %}`ed macros
  capture the module's frame and lose the importing render's context;
  `with context` copies the importer's visible names into the module frame at
  import time — a snapshot, so a later `{% set %}` is invisible to them.

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

**A filter's arguments are operands too.** A markup result may only be assembled
from operands that are themselves markup or have been escaped — a filter that
splices a caller-supplied argument into a result it then marks as markup makes
`autoescape` bypassable *without `|safe`*, because a `{% set %}` / `{% filter %}`
body is markup by construction: `{% filter replace('x', data) %}…{% endfilter %}`
would emit `data` raw in a template that never marks anything safe. `|replace`
and the `.replace()` method therefore follow the reference exactly — Jinja2's
`do_replace` escapes the subject when either argument is markup, markupsafe's
`Markup.replace` escapes `new` and leaves `old` unescaped (so `old` is matched
against the raw markup bytes) — and the corpus crosses `autoescape=true` with
every argument-taking filter, each argument carrying `<`, `>`, `&`, `"` and `'`.

The one exception is **`|indent` with a *string* width**, which Jinja2 splices
raw into a markup result (`do_indent` does `indention = Markup(indention)`, and
`Markup(x)` does not escape `x`). We match the reference there, which makes it
the only route from context data to unescaped output that does not spell
`|safe` — `escape_indent_string_width_splices_raw` pins it.

## 6. Divergences from Python Jinja2 3.1.6

Everything not covered by a corpus case is here. Nothing in this table is a
relaxed test; each is either a compile error (so a caller meets it immediately)
or a documented, tested behaviour.

| # | Divergence | Kind |
|---|---|---|
| D1 | Default `undefined_policy` is `.strict` (see §4) | default, opt-out |
| D2 | i18n (`{% trans %}`/`{% pluralize %}`) and the `{% autoescape %}` block are not implemented — autoescaping is an environment option here, not a per-region switch | **compile error naming the tag** |
| D3 | Integers are `i64`; Python's are arbitrary precision. Overflow is `error.OutOfRange` where Python grows the number | runtime error |
| D4 | `upper`/`lower`/`capitalize`/`title` and the `is upper`/`is lower` tests are ASCII-only; Python applies Unicode case mapping. Length, indexing, slicing and iteration of strings *are* codepoint-correct | silent, ASCII-identical |
| D5 | `map`/`select`/`reject`/`selectattr`/`rejectattr`/`items`/`dictsort`/`batch`/`slice` return lists, not generators, so rendering one directly prints `[…]` where the reference prints `<generator object …>` | silent, strictly more useful |
| D6 | Filters absent: `attr`, `filesizeformat`, `format`, `groupby`, `pprint`, `random`, `urlize`, `wordwrap` | **compile error** |
| D7 | Tests absent: `callable`, `sameas`, `filter`, `test`, and the symbolic aliases (`is ==`, `is >`, …) — the named forms `eq`, `gt`, … are present | **compile error** |
| D8 | Globals absent: `lipsum`, `cycler`, `joiner` | **compile error** |
| D9 | `*args`/`**kwargs` *at a call site*, line statements/comments, and custom delimiters (macro `varargs`/`kwargs` on the receiving side are implemented) | **compile error** |
| D10 | `{% do %}` and `{% with %}` need no extension to be enabled | superset |
| D11 | String methods are a documented subset (README); an unknown one is a render error naming the type and method | runtime error |
| D12 | `round(x, p)` falls back to scaled arithmetic when the exact integer form would exceed `u128` (roughly `|p| > 22`) | silent, beyond f64 precision |
| D13 | `max_output_bytes` (64 MiB), a 4 Mi-element cap on `range()`/`'x' * n`, and `max_nesting_depth` (256) have no reference equivalent. The reference has no explicit nesting bound either, but CPython's recursion limit gives it an implicit one that is *tighter* for nested source: Jinja2 3.1.6 raises `RecursionError` for `{{ ((…1…)) }}` between 50 and 100 parentheses | extra refusal |
| D14 | A loader is explicit: without one, a composition tag is `error.NoLoader`. There is no implicit filesystem access and no default search path | API |
| D15 | Calling a name that is not a macro and not one of the three built-in globals is `error.NotCallable`; the reference would call any callable in the context | **runtime error** |
| D16 | `super.super()` (reaching two levels up in one expression) is not implemented; `{{ super() }}` inside a block that itself overrides is the supported form | **runtime error** |
| D17 | A template name a loader *refuses* (an escape attempt) is `error.LoaderFailed` even under `ignore missing` — only genuine absence is ignorable | deliberate, stricter |

Why `attr` was dropped rather than implemented (D6): the reference's `attr`
filter is `getattr` *without* the `getitem` fallback, so applied to a mapping —
which is what every context value here is — it returns undefined, always. A
filter that can only ever produce undefined is a trap; a compile error saying it
does not exist is better than a faithful no-op. `map(attribute=…)` and
`selectattr` keep working on mapping keys, because those use the fallback path in
the reference too.

## 7. Verification

The anchor is **Python Jinja2 3.1.6**, the reference implementation, and the
comparison is byte-for-byte: `src/corpus.zig` holds 330 cases (template + the
other templates its loader serves + JSON context + syntax options), and both
oracles render exactly that table — Zig against a `MapLoader`, Python against a
`DictLoader` built from the same table.

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

**Load-bearing check.** The oracle is verified to be load-bearing by mutation,
once per surface. For the expression engine: changing `pyMod` from Python's
floored remainder to `@rem` (C truncation) — a change no unit test notices —
turns `mod_negatives` red in both oracles (`1|1|-1|-1` vs `1|-1|1|-1`). For
composition: making every `{% block %}` behave as if it were `scoped` — the
single most tempting simplification in the whole inheritance implementation,
and one that no self-written test would catch because it makes blocks see
*more* — turns `block_in_for_is_not_scoped_by_default` red in both oracles
(`<><>` vs `<1><2>`). Both mutations were reverted.

**What the corpus is weighted towards.** Not the easy paths: whitespace-control
combinations including `+` and the option interactions, `loop` inside nested
loops, `{% set %}` scoping inside a loop body versus `namespace()`, floor
division and modulo on negative operands in both int and float, banker's
rounding at ties and at values like `2.675` that are not the decimal they look
like, filter argument evaluation, autoescape interacting with `|safe`/`|escape`/
`~`/`|join`, `repr` of every value kind, and the cases where the reference
*errors* (each marked, and required to fail on our side too).

For composition specifically: `super()` in a three-level chain and across a
level that does not define the block, a block inside a `{% for %}` with and
without `scoped`, a child's top-level `{% set %}` reaching its blocks, an
`{% extends %}` whose name comes from a `{% set %}` above it, `{% set %}`
visibility across an `{% include %}` in both directions, `import` with and
without context and the snapshot-vs-view question, a macro reading a module-level
`{% set %}` written *after* it, `caller()` with positional and keyword arguments
and a caller body that reads the enclosing loop, macro `varargs`/`kwargs` and the
argument counts that must be *refused*, recursive loops with `loop.depth`, and
composition crossed with autoescape and with whitespace control.

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
`{% for i in range(10**9) %}` fail rather than being attempted, and `**` is
answered in closed form for the bases (`0`, `1`, `-1`) whose loop would
otherwise run `exponent` times producing no output for `max_output_bytes` to
see.

Recursion in the parser and in the evaluator follows the source's nesting depth,
and that is bounded explicitly by `max_nesting_depth` (256), not implicitly by
anything about the source. An earlier revision of this section claimed the
recursion was "bounded by the source's bracket nesting", which restated the
problem rather than solving it: 8 000 nested parentheses (a 16 KB template),
8 000 `|string` links and 16 000 nested `{% if %}` each overflowed the stack.
One `Options` field now bounds all three, at compile time, as `error.TooDeep`
with a diagnostic — and because it bounds the *tree*, it bounds `Renderer.eval`,
`renderNodes` and the macro-body walker too. Siblings do not accumulate, so
template size is not limited; only depth is.

Escaping is a policy the caller sets, not a guess: with `autoescape = false` the
module never escapes anything, and with it on the safe bit is the only way to
opt a value out. Because `|safe` is representable in a value, a caller can mark
trusted fragments in the *context* rather than in the template.

**`autoescape` is HTML-*text*-context escaping only, and covers exactly what
markupsafe's escape set covers: `&` `<` `>` `"` `'`.** There is no backslash in
that set and no URI-scheme validation, so a value interpolated into a
`<script>` block or a `href`/`src` attribute is not made safe for *that*
context by `autoescape` alone: `<script>var a = "{{ s }}";</script>` with
`s = "\\"` still lets the value escape the JS string (no backslash-escaping),
and `<a href="{{ u }}">` with `u = "javascript:…"` still emits the scheme
intact. This is not a divergence from the reference — Jinja2 has exactly the
same scope, verified live in all three contexts (script, attribute, URL body)
byte-identical to this module — so it is not a bug to fix here, only a scope
this section previously left unstated. A caller who interpolates into a
`<script>` block wants `|tojson`; a caller who interpolates into a URI
attribute needs its own scheme allow-list, same as with the reference.

## 9. The loader and Zig's ownership model

The brief for this half sketched the loader as plumbing. One thing about it is
not plumbing, and it is worth writing down because the obvious design costs a
property Part 1 established.

The reference caches **compiled templates** on the environment: `get_template`
is memoised, and a render reaches into that cache. Doing the same here would
mean a render needs `*Environment` rather than `*const Environment` — and with
that, `Template` stops being immutable and two threads rendering the same
template race on the cache. The alternatives are a lock inside `Environment`
(paid by every consumer, including single-threaded ones) or giving that up.

So the cache is **per render, in the render arena**. `Environment` holds only
the `Loader` and stays `const` throughout; a template loaded during a render is
compiled at most once for that render (so an `{% include %}` inside a loop is
linear, and a diamond inheritance graph loads each side once) and is thrown away
with the arena. The cost is recompilation across renders; the gain is that
`Template` remains immutable, `Environment` remains shareable, and lifetimes are
trivially correct — a loaded template's bytes and tree live exactly as long as
the render that asked for them, which is the one thing a borrowed-source loader
API makes easy to get wrong.

If recompilation ever shows up in a profile, the fix is a caller-owned cache
passed *into* `render`, not a mutable environment.

## 10. Loader containment and expansion bounds

Part 1 had no way to name another template. Part 2 has one, so it has an attack
surface, and it is treated as one.

### Path containment

`DirLoader` enforces containment twice, and the second half is the load-bearing
one:

1. **Lexically** (`checkName`, exported so a caller's own loader can reuse it):
   an absolute path, a `..` or `.` component, a backslash, a NUL, an empty
   component, an over-long name or component — all refused. `..` is *rejected*,
   never resolved: accepting `a/../b` would require this checker and the kernel
   to agree about normalization, and every containment bug of this class is a
   disagreement about exactly that.
2. **Structurally**: the path is walked one component at a time, each directory
   opened relative to the previously held handle with `follow_symlinks = false`,
   and the final file opened the same way.

The brief anticipated that symlink containment might not be achievable without
`openat`-style primitives. In Zig 0.16 it is: `std.Io.Dir.openDir` and
`openFile` both take `follow_symlinks`, and `openFile` additionally takes
`resolve_beneath`. Walking components with `follow_symlinks = false` gives a
**portable** guarantee that does not depend on the kernel — no symlink anywhere
along the path is traversed, so a link planted inside the root cannot redirect a
read outside it. Because every open is relative to a held file descriptor rather
than to a re-resolved string, there is also no check-then-open window for
anything to be swapped underneath. `resolve_beneath` is requested as well but
nothing depends on it: std documents it as *silently ignored* where unsupported,
which makes it unfit to be the guarantee.

**What this deliberately does not promise:**

- It is **stricter than containment requires**. A symlink pointing at another
  file *inside* the root is refused too. `allow_symlinks = true` trades the
  portable guarantee for the kernel's (`resolve_beneath` alone: airtight on a
  Linux with `openat2`, absent elsewhere) — a documented downgrade, not a
  default.
- A hard link inside the root to a file outside it is **not** detectable this
  way, and is not claimed to be. A hard link needs write access to the root
  already; if an attacker has that, they can simply write a template.
- The bound is on *reading through the loader*. It says nothing about what a
  caller's own `Loader` does, which is why `checkTemplateName` is exported.
- A refused name is `error.LoaderFailed`, and `ignore missing` does **not**
  swallow it (D17). Only genuine absence is ignorable; an escape attempt is a
  signal, not a missing file.

Tested by attack, not by assertion (`loader_test.zig`): a real tree is built
with a secret outside the root and both a symlinked file and a symlinked
*directory component* pointing at it, and twelve escape spellings plus both
symlink routes are attempted through the loader — including a name arriving from
the render context rather than from template source, which is the realistic
shape (`{% include theme %}`).

### Cycles and unbounded expansion

Two mechanisms, because they answer different questions:

- **An inheritance cycle is caught by name.** While the `{% extends %}` chain is
  built, each parent is checked against the chain so far; `a extends b extends a`
  is `error.TemplateCycle` immediately, at chain-building time, before anything
  renders. A depth cap alone would catch it too, but only after doing the work.
- **Everything else is caught by a depth cap.** `max_template_depth` (32) bounds
  `{% extends %}` + `{% include %}` + `{% import %}` nesting combined;
  `max_call_depth` (64) bounds macro calls, `{% call %}` bodies and `loop()`;
  `max_templates` (256) bounds distinct loads per render; `max_nesting_depth`
  (256) bounds expression, chain and block nesting within one template; and
  `max_output_bytes` bounds the output. All are `Options` fields.

The proof is a set of bombs, not a comment. `loader_test.zig` renders a
self-including template, a mutually-including pair, an **exponential** include
bomb (each level includes the next twice — the shape that cost this repository's
author a desktop and 15.4 GB elsewhere), an infinitely recursive macro, a
mutually recursive macro pair, a self-feeding recursive loop, and an import
cycle. Each assertion is on the *specific* cap error, with the render arena
confined to a 1 MiB `FixedBufferAllocator`: a bomb that outran its bound would
exhaust the buffer and come back `OutOfMemory`, failing the test. That is what
makes these bound tests rather than "it errored eventually" tests.

## 11. Backlog

- The eight absent filters (D6). `groupby` and `pprint` need a decision about
  what to render for a namedtuple and for Python's pretty-printer layout before
  they can be byte-exact; `random` needs a seed in the environment to be
  testable at all; `wordwrap` needs `textwrap`'s exact algorithm.
- i18n (`{% trans %}`) and the `{% autoescape %}` block (D2). The latter needs
  autoescaping to become a per-region property of the renderer rather than an
  environment option; worth doing only alongside the former.
- `super.super()` (D16) and callables in the context (D15) — both small, both
  waiting for a consumer that wants them.
- Line statements and configurable delimiters — cheap in the lexer, wanted only
  if a real consumer asks.
- A caller-owned template cache passed into `render` (§9), if recompilation ever
  shows up in a profile.
- A lazy context adapter (§2), if a context ever appears that is too large to
  convert eagerly.

# yaml — design & threat model

Purpose and API: see [README.md](README.md).

Reference: **YAML 1.2.2 specification**, yaml.org/spec/1.2.2 (section numbers
below refer to it). Written from that text plus the yaml-test-suite's own
expected outputs. No existing YAML implementation's source was read or ported;
where the spec and a suite expectation appeared to disagree, the suite won and
the reasoning is recorded at the call site.

## 1. Why the stages are separate

```
bytes ─► scanner.zig ─► parser.zig ─► Event ─► compose.zig ─► Value
         tokens         state machine          + core schema
                                      └──────► events.zig (test.event text)
```

The split is load-bearing, not decorative. Two of YAML's hardest features are
*scanner* problems and become intractable if fused into the parser:

- **Synthesized structure tokens.** `block_sequence_start`,
  `block_mapping_start` and `block_end` have no textual form. The scanner keeps
  `indent` (the column of the innermost open block collection, -1 for none) and
  a stack of outer indents; any token starting left of `indent` unrolls the
  stack, emitting one `block_end` per level. That is the *entirety* of YAML's
  block-closing logic — the parser never sees a column.

- **Retroactive key insertion.** When the scanner emits a scalar it does not yet
  know whether the scalar is a mapping key. It records a `SimpleKey` holding a
  position in the *token queue*, and when a `:` arrives it splices a `key`
  token — and in block context a `block_mapping_start` — into the queue *before*
  the already-emitted scalar. This is why the queue is an `ArrayList` with a
  head index rather than a FIFO.

`events.zig` is deliberately separate and trivial: it is the serialization the
external oracle speaks, and keeping it out of the parser means the event model
is not shaped by a test format.

`compose.zig` is separate for a different reason: it is the only stage that is
*lossy*. Scalar style, which nodes were aliases and the text of unrecognised
tags all stop existing once a `Value` exists, and a consumer that needs them has
to be able to tap the stage below. Fusing the two would delete that option.

## 2. Termination — the invariant that matters most

A parser that can spin on malformed input is a denial-of-service defect in its
own right, and **94** of the suite's 402 cases are deliberately malformed, so
any such path *will* be reached. This module had exactly that bug; the fix is
structural rather than an iteration cap.

**The bug.** A bare `[` (unterminated flow sequence) saved a simple key at the
outer level and then hit EOF. `fetchStreamEnd` cleared only the *innermost*
simple key, so the outer one stayed `possible`; `needMoreTokens` treats a
possible simple key at the queue head as "cannot hand this out yet", so it
returned true forever. `Scanner.peek`'s loop therefore called `fetchNextToken`
again and again, and at EOF that unconditionally enqueued a *fresh* `stream_end`
token every time. Unbounded token-queue growth — measured at **15.4 GB RSS**
before the host's OOM killer took the whole desktop with it.

**The guarantees now in place**, in the order they fire:

1. **Stream end invalidates every pending simple key**, not just the innermost.
   This is the correctness fix: the queue unblocks legitimately and `[` is
   rejected with "did not find expected node content".
2. **`stream_end` is produced at most once and is sticky.** `fetchNextToken`
   returns immediately once it has been produced, and `Scanner.next` refuses to
   pop it, so the queue can never drain back to empty. The token stream is
   monotone and finite by construction, and no caller can walk off the end.
3. **`Scanner.peek` asserts progress.** Every `fetchMoreTokens` must either
   advance `pos` or grow the queue. `pos` is monotone and bounded by
   `src.len`, and past EOF (2) makes a fetch a no-op, so any residual state that
   cannot make progress surfaces as one bounded `error.InvalidYaml` instead of
   an infinite loop. This is what guards the *class* rather than the instance.
4. **`readLine` never appends without consuming.** `skipLine` is a no-op off a
   line break, which made `readLine` an append-without-consume primitive — the
   exact shape that turns a mis-guarded caller into unbounded allocation. The
   guard is now a property of the primitive, not of each of its call sites.
5. **The parser bounds token-free events.** The scanner being monotone does not
   stop a *state machine* from cycling. Every event emitted without consuming a
   token is an implicit empty scalar or a collection close, each of which must
   strictly shrink the state stack; the stack is bounded by `max_depth`, so a
   run of token-free events longer than that is necessarily a cycle. `next()`
   checks that and fails.

`max_depth` (4096) additionally bounds `indents`, `flow_level` and the parser's
state stack, so nesting cannot be used to exhaust memory. The suite's deepest
case nests 8 levels.

## 3. Rules worth recording

Places where the correct behaviour is not what a first reading of the spec
suggests, each pinned to the suite cases that establish it:

- **Between-documents position.** A *bare* document and a `%`-directive are
  legal only at stream start or immediately after an explicit `...` footer, and
  a stray `...` is a no-op that re-opens that position. Both halves matter:
  `HWV9`/`QT73` need a lone `...` to produce no document at all, `7Z25` needs a
  bare document to follow one, and `9HCY`/`EB22`/`RHX7` need a directive with no
  preceding footer to be *rejected*. §9.1.
- **`...` takes only a comment after it** (`l-document-suffix`, §9.1.4), so
  `... invalid` is an error rather than a fresh document (`3HFZ`). `---` has no
  such restriction.
- **Implicit-key span differs by context**, and this is the subtlest rule in the
  scanner. Block context and a flow *sequence* single-pair both use
  `s-separate-in-line` — one line only. A flow *mapping* entry uses `s-separate`,
  which admits a line break, so `{ k\n : v }` is legal while `[ k\n : v ]` is
  not. Compare `NJ66`/`9SA2`/`VJP3/01` against `DK4H`/`ZXT5`. §7.4. The scanner
  tracks the kind of each open flow collection (`flow_is_seq`) purely for this.
- **Empty keys in flow.** `{: v}` and `[: v]` have no scalar for the scanner to
  promote into a `key` token, so it emits a bare `value`; the empty scalar key
  is synthesized in the parser (`CFD4`, `FRK4`, `NKF9`).
- **Line-start accounting belongs to the cursor.** Leading blanks are consumed
  from three places — `scanToNextToken` and the continuation folding loops of
  both `scanPlainScalar` and `scanFlowScalar`. Maintaining `line_spaces` in only
  the first made it under-report the indentation of any line a folded scalar had
  already walked into, and the flow-indent check then rejected valid documents
  (`ZF4X`, `VJP3/01`, `LP6E`).
- **A minor `%YAML` version we do not know is a warning, not an error** (§6.8.1):
  `%YAML 1.3` parses as 1.2 (`BEC7`). Only a different *major* version is fatal.
- **Block-scalar indentation detection has two distinct faults**, needing two
  different comparisons: an empty line deeper than the first content line
  (compare against the deepest empty line seen — `S98Z`), and a blank line that
  stops short of the detected indent because a tab was offered as the missing
  indentation (compare against the detected indent — `Y79Y/000`, vs `Y79Y/001`
  and `R4YG` where a space reaches it, and `96NN` where a tab is just content).
  Using one comparison for both condemns a block scalar that simply has no
  content (`K858`).
- **A stream ending without a final break** is treated as if it had one (§5.4),
  but only for a *content* line. Ending on the block-scalar header itself
  (`--- |1+`) leaves no break for `+` to keep (`2G84/02`, `2G84/03`), while a
  trailing all-blank line does (`JEF9/02`).
- **Line breaks are LF and CR only.** YAML 1.1's NEL/LS/PS are plain content in
  1.2 (§5.4).

## 4. Threat model

Input is bytes the module did not produce, so the bar is **never panic, never
loop, never allocate without bound on arbitrary input** (CONVENTIONS.md §7.1).

- *Unbounded loops / allocation* — §2 above.
- *Panics on malformed UTF-8* — the cursor advances by a computed character
  width and clamps to `src.len`; a stray continuation byte consumes one byte.
  Scalar text is passed through as bytes and never decoded, so no case can index
  past the end. Invalid UTF-8 is **not** rejected: this layer is byte-transparent
  and validation belongs to the composer.
- *Nesting exhaustion* — bounded by `max_depth` (§2), and independently by the
  composer's own `Options.max_depth`, which also keeps `composeNode`'s recursion
  off the end of the stack.
- *Alias expansion bombs* — aliases share rather than copy, so "billion laughs"
  composes into O(n) nodes rather than O(2^n); `Options.max_nodes` bounds the
  total regardless. Cyclic aliases are rejected outright (§7).
- *Quadratic behaviour* — a simple key is abandoned after 1024 characters, so
  the retroactive-insertion lookahead cannot be driven arbitrarily far.
- *Panics generally* — `test "arbitrary input never panics"` drives 4000
  adversarial strings over the full indicator alphabet through `dumpEvents`;
  every outcome except a crash is acceptable. That assertion only carries
  meaning in a build where safety checks exist (§7.1) — it is evidence about a
  Debug or ReleaseSafe consumer, not a ReleaseFast one.

## 5. Verification

The whole verification story is the external anchor, because self-written tests
share whatever this code misreads about YAML. yaml-test-suite anchors **both**
layers, and one ledger (`src/testdata/ledger.txt`, harness in
`src/suite_test.zig`) carries one row per case with all of its expected
outcomes:

| layer | oracle | score |
|---|---|---|
| events | `test.event`, byte-exact | **402/402**, incl. all 94 must-reject |
| values | `in.json`, structural | **279/279** |

279 and not 282: three `in.json` files belong to must-reject cases, where they
are a truncated artefact rather than a pass condition — the same trap
`test.event` sets for the event layer. A further 29 non-error cases ship no
`in.json` at all, because their YAML has non-string mapping keys and so has no
JSON form.

**What the JSON oracle cannot police is int vs float.** JSON has one number
type; whether a literal carries a `.` is a choice of whatever serialiser wrote
the file. The suite settles it: `UGM3`'s YAML says `450.00` — a float beyond
argument — and its `in.json` says `450`. Numbers are therefore compared by
*value* across both kinds, never through a formatted string, while every
distinction JSON genuinely makes (number vs string vs bool vs null vs array vs
object) stays exact — which is where the core-schema bugs worth catching live.
The int/float resolution itself is pinned by `compose.zig`'s unit tests, the
only place it can be.

Both anchors were checked to be load-bearing rather than assumed, by mutation:

| mutation (one line) | cases turned red |
|---|---|
| block-scalar chomping default clip → strip | **63** events |
| core schema applied to quoted scalars too | **4** json |
| aliases resolve to `null` instead of the anchored node | **13** json |
| core schema removed — every plain scalar stays a string | **54** json |

Each failure names the case and, for the value layer, the path inside it
(`doc0.product[0].price: yaml=float json=integer`). The ledger's other
direction and its cross-checks were verified the same way: fabricating a
known-fail, deleting a row, claiming a JSON oracle for a case that has none, and
writing an incoherent row (`events fail` with a JSON claim) are each red.

The suite is not vendored. It is a separate repository with its own history, and
pinning a copy here would turn a live oracle into a stale one; the harness skips
loudly when it is absent.

## 6. The core schema, and what "1.2 core" excludes

Resolution order for an untagged **plain** scalar is null, bool, int, float,
str (§10.2.2). Three things are worth stating because they are where a YAML
implementation quietly becomes a 1.1 one:

- **No `yes`/`no`/`on`/`off` booleans.** Only the `true`/`True`/`TRUE` and
  `false`/`False`/`FALSE` sextet. A config reader that treats `no` as false is
  reading 1.1.
- **No bare-leading-zero octal, and no sexagesimals.** `0777` matches
  `[-+]?[0-9]+` and is decimal **777**; octal is spelled `0o777`. `1:30` is a
  string.
- **Only plain scalars are resolved at all.** `"true"`, `'42'` and any literal
  or folded block scalar are strings whatever they spell.

The float *shape* is validated here rather than delegated to
`std.fmt.parseFloat`, which is far more permissive: it accepts bare `inf`,
`nan` and hex floats, none of which the core schema resolves as numbers. Only
`.inf`/`.nan` (with their case variants) are float.

An explicit tag overrides resolution. A tag the core schema does not know —
`!foo`, `!<!bar>`, `tag:example.com,2000:app/light` — leaves the scalar as its
literal text: only the application that defined the tag can say what it means,
and guessing is worse than handing over the bytes. The suite agrees (`5TYM`,
`CC74`, `6WLZ`, `7FWL`).

## 7. Cyclic aliases — rejected, deliberately

YAML 1.2 §3.2.1 permits a **cyclic** representation graph: an alias may name an
ancestor, as in `&a [ *a ]`. This composer rejects that with
`error.AliasCycle`. The decision, and why it is not merely the easy option:

1. **A cyclic `Value` is unusable by its own consumers.** `Value` is a by-value
   union that any Zig program can walk with ordinary recursion. Admit cycles and
   every consumer — equality, serialization, a config reader looking for one
   key — must carry a visited-set or hang. That cost lands on every user of the
   API to serve a construct essentially no real document uses.
2. **Rejection is a security posture, not just a simplification.** A cyclic
   alias is an unbounded-expansion primitive; any consumer that walks the graph
   without expecting cycles becomes a hang or an OOM on hostile input.
3. **No oracle requires the alternative.** JSON cannot represent a cycle, so no
   `in.json` case in the suite exercises one, and nothing was traded away to get
   the score in §5.

The detection is **structural rather than a graph search**: a collection
registers its anchor *before* composing its children, marked in-progress, and an
alias that resolves to an in-progress anchor is by definition an ancestor
reference. A cycle is therefore never constructed in the first place, which is
precisely what lets `Value` stay a plain by-value union.

Aliases that are *not* cycles **share** the anchored node rather than copying
it. That is also the defence against the "billion laughs" bomb (`&a [x,x]`,
`&b [*a,*a]`, `&c [*b,*b]`, …): each alias costs one union copy, so an input
that would expand to 2^n nodes composes into n. A consumer that walks the DAG
*as if* it were a tree still sees 2^n paths — inherent to the format, and why
`Options.max_nodes` exists as a second bound.

The anchor **table** is a third, easily missed cost. Nothing in the format caps
how many anchors a document may declare — an anchor is one `&name` token, and
`max_nodes` bounds nodes rather than comparisons — so a table that is scanned
linearly on definition *and* on alias resolution makes composing O(anchors²).
Measured on the array-scan version (ReleaseFast, best of 5): 8.7 / 35.5 /
142.5 ms at 2000 / 4000 / 8000 anchors = 4.0× per doubling, against 1.11 / 2.16 /
4.74 ms = 1.95× for the same document with the anchors removed — a 128 KB input
already 30× the anchor-free cost, and the ratio grows with n. With the index:
1.26 / 2.47 / 5.28 ms = 2.0× per doubling, 1.2× the anchor-free control.
`Composer` therefore keeps a name → slot index beside the array; the array
remains the storage so slot identity and `finishAnchor` are unchanged. Pinned by
`compose.zig`'s `anchor_probes` counter rather than by a wall-clock assertion.

## 8. Integer range — the one place resolution is lossy

`Value.int` is an `i64`. An int-shaped scalar that does not fit stays a
**string** holding its exact original text, tagged or not.

The alternative that had to be ruled out is worse and was live in an early
draft: `parseFloat` accepts bare digits, so falling through to the float branch
turned `123456789012345678901234567890` into `1.2345678901234568e29` — a silent,
lossy reinterpretation of a value the schema says is an integer. Testing int by
*shape* first, and never falling through on a shape match, is what prevents it.

No suite case exercises this (the corpus has no oversized integers), so the unit
test in `compose.zig` is the only thing keeping the behaviour deliberate. A
consumer needing bignums has the exact text and can parse it itself.

## 9. Backlog

- **Emitter, `parseInto(T, …)`, schemas beyond core** — see README, Deferred.
- **Fuzz harness.** The module ships an adversarial-input test but not yet a
  `std.testing.fuzz` target wired into the repo's fuzz corpus, which is where a
  parser of this size belongs.
- **`problem`/`problem_mark` are best-effort.** The first error wins, and marks
  point at the scanner cursor rather than always at the offending construct's
  start. Good enough to debug with, not yet good enough to render a caret
  diagnostic against.
- **UTF-16/UTF-32 input.** §5.2 allows a BOM to select them; only the UTF-8 BOM
  is handled (and skipped), other encodings are not detected.

# yaml — design & threat model

Purpose and API: see [README.md](README.md).

Reference: **YAML 1.2.2 specification**, yaml.org/spec/1.2.2 (section numbers
below refer to it). Written from that text plus the yaml-test-suite's own
expected outputs. No existing YAML implementation's source was read or ported;
where the spec and a suite expectation appeared to disagree, the suite won and
the reasoning is recorded at the call site.

## 1. Why three stages

```
bytes ──► scanner.zig ──► parser.zig ──► Event ──► events.zig (test.event text)
          tokens          state machine
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
- *Nesting exhaustion* — bounded by `max_depth` (§2).
- *Quadratic behaviour* — a simple key is abandoned after 1024 characters, so
  the retroactive-insertion lookahead cannot be driven arbitrarily far.
- *Panics generally* — `test "arbitrary input never panics"` drives 4000
  adversarial strings over the full indicator alphabet through `dumpEvents`;
  every outcome except a crash is acceptable. That assertion only carries
  meaning in a build where safety checks exist (§7.1) — it is evidence about a
  Debug or ReleaseSafe consumer, not a ReleaseFast one.

## 5. Verification

The whole verification story is the external anchor, because self-written tests
share whatever this code misreads about YAML: **402/402 of yaml-test-suite**,
including all 94 must-reject cases, asserted against a committed ledger in both
directions (`src/testdata/ledger.txt`, harness in `src/suite_test.zig`).

The anchor was checked to be load-bearing rather than assumed: mutating the
block-scalar chomping default from clip to strip — one character — turned **63**
cases red, each named individually. The ledger's reverse direction was checked
the same way: marking a passing case as a known-fail, and deleting a case from
the ledger, are both red.

The suite is not vendored. It is a separate repository with its own history, and
pinning a copy here would turn a live oracle into a stale one; the harness skips
loudly when it is absent.

## 6. Backlog

- **Part 2** — composer, core schema, native values, emitter (README, Deferred).
- **Fuzz harness.** The module ships an adversarial-input test but not yet a
  `std.testing.fuzz` target wired into the repo's fuzz corpus, which is where a
  parser of this size belongs.
- **`problem`/`problem_mark` are best-effort.** The first error wins, and marks
  point at the scanner cursor rather than always at the offending construct's
  start. Good enough to debug with, not yet good enough to render a caret
  diagnostic against.
- **UTF-16/UTF-32 input.** §5.2 allows a BOM to select them; only the UTF-8 BOM
  is handled (and skipped), other encodings are not detected.

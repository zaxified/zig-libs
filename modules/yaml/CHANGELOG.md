# yaml — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 fix campaign, F10 (found mid-fix during the second pass above;
  0 consumers in this repo, P1 applies). `composeNode` recurses one native call frame
  per nesting level, and `account()`/the duplicate-key check trusted `Options.max_depth`
  outright — nothing stopped a caller from raising it past `scanner.max_depth` (4096).
  That field looks like a second, independent safety net; it is not one, because the
  scanner and parser are iterative (no per-level recursion). A caller-raised `max_depth`
  therefore let `composeNode`'s own recursion run deep enough to overflow Debug's native
  stack — SIGSEGV, not a catchable error — well before the scanner's own cap would have
  refused the input (measured while finding this: SIGSEGV composing a 4096-deep tree
  with `max_depth` raised to accommodate it). Fixed by clamping the depth ceiling
  actually enforced (`Composer.effectiveMaxDepth`, new `compose.max_safe_depth = 1024`
  constant) to the one depth this module has proven Debug-stack-safe — the shipped
  default — regardless of what `Options.max_depth` is set to; `@min` only ever tightens
  a caller's own setting, never loosens it, so this is a no-op for every caller at or
  below the default. New regression test proves the clamp without going near the crash
  itself: reuses the exact depth (1025) an existing test already recurses to safely, and
  shows `max_depth = 100_000_000` no longer lets composition past it (RED: composed
  successfully instead of `error.TooDeep`; GREEN: `error.TooDeep`, matching the default's
  own boundary). scripts/modtest yaml: 59/59, Debug and ReleaseFast alike.

- **2026-09-10** — A1 fix campaign, second-pass fix queue (0 consumers in this repo, P1
  applies): test-only, no production behavior change except where noted. `scanner.zig`'s
  OWN `max_depth = 4096` flow/block-nesting cap (a lower-level guard than the composer's
  `Options.max_depth`, which F1-F3 already cover) had zero test coverage — added two
  scanner-level tests (`scanner.zig`, bypass the composer entirely so there is no
  per-level recursion to overflow Debug's stack) pinning the exact boundary for both flow
  (`[[[...`) and block (`- \n  - \n...`) nesting; verified against the audit's own mutation
  shape (the guard replaced with `if (false)`) that both catch it. Added a test that an
  alias name which is a superstring of a real anchor (`*ab` when only `&a` is defined)
  stays `error.UnknownAlias` — already correct (the anchor table is an exact-match
  `StringHashMapUnmanaged`), but a mutation adding a "try one byte shorter" fallback
  wasn't caught by anything before this (F5, partial — `R08`'s parser liveness invariant
  and the block/flow-nesting `simple_key`/tab-indent survivors from the audit's mutation
  table remain untested). `root.zig`'s "arbitrary input never panics" stand-in fuzzer
  (not gated behind `--fuzz`, always runs) drew from a pure-ASCII indicator alphabet and
  could never produce the invalid-UTF-8/control-byte class F4 needed — broadened it to
  include one byte from each invalid-lead-byte class F4 named plus NUL/DEL/ESC; measured
  0/4000 to 3729/4000 draws reaching that byte class (F8, partial — `compose.zig`'s two
  `testing.fuzz` harnesses turned out to already be unrestricted, a side effect of an
  unrelated Smith-vacuity fix, `97583a0a`, 2026-09-07, confirmed by diffing that commit's
  parent; not something this pass did).
  Open, deferred: F7 and F9 are user decisions per the audit's own §6 (points 4 and 6);
  F5's remaining survivors (parser liveness invariant, simple-key length cap, tab-indent
  state) need more test-writing time than this slot had. scripts/modtest yaml: 58/58,
  Debug and ReleaseFast alike.

- **2026-09-10** — A1 audit fix campaign, `A1/yaml.md` F1/F2/F3/F4/F6 (0 consumers in
  this repo, P1 applies). The default-on duplicate-key check (`Options.reject_duplicate_keys
  = true`) walked composed `Value`s with plain, unmemoized structural equality: an
  alias-sharing document could force up to 2^n comparisons for n levels of anchor
  sharing regardless of whether the comparison found a duplicate or not (F1, measured
  13.4 s / 666 B and 3.7 s / 1.2 KB), an ordinary map with k distinct scalar keys and
  no aliases at all was a separate O(k²) linear scan (F2, measured 17.6 s at k=64 000,
  352× its own control), and the same unbounded recursion could walk a syntactically
  shallow but alias-deep value past any real stack (F3, measured SIGABRT/SIGSEGV at
  n=200 000). Replaced with `DupTracker`: scalar keys go into a hash set (O(1) amortized,
  closes F2), sequence/mapping-typed keys use a new `dupEql` that memoizes per
  `(pointer, pointer)` sub-comparison and is bounded by `Options.max_depth` (closes F1's
  exponential blowup and F3's stack overflow — `error.TooDeep` instead of a crash).
  Measured after the fix, same shapes: F1 wide-bomb 13.7 s → 0.2 ms, F1 "succeed" variant
  3.7 s → 0.1 ms, F2 64 000-key map 15.5 s → 62.7 ms, F3 200 000-deep chain SIGABRT →
  1.9 s clean `error.TooDeep`. Separately, `scanner.charWidth` treated every byte ≥ 0xF0
  as a 4-byte UTF-8 lead, including 0xF5-0xFF which can never start a valid sequence
  (RFC 3629 §3); one such byte before a structural character (`:`, `\n`) swallowed it and
  silently changed the document's shape (F4) — fixed to consume one byte for 0xF5-0xFF,
  same as every other invalid lead byte; this layer still does not validate UTF-8 (open,
  SPEC.md §10). And a leading UTF-16/UTF-32 BOM, previously read as ordinary content and
  folded into one nonsense scalar, is now rejected with `error.InvalidYaml` (F6) instead of
  a silent wrong-document result a caller's `.get()` default could mask. Five permanent
  regression tests added (`compose.zig`), pinned on `Composer.dup_probes` — a deterministic
  step count in the same style as the existing `anchor_probes` — rather than a wall clock.
  F5 (missing tests for other DoS-relevant caps), F7 (escaped astral surrogate pairs
  rejected), F8 (fuzz harnesses miss non-ASCII input) and F9 (`max_nodes` bounds nodes,
  not heap bytes) remain open — see `A1/yaml.md` dispozice.
- **2026-09-07** — Both composer fuzz targets ran one fixed input for their whole existence.
  `fuzzComposeNeverPanics` drew its length with `smith.valueRangeAtMost(u16, 1, 512)` and each
  character with `smith.index(alphabet.len)`; a ranged `Smith` draw reads eight octets as a
  little-endian `u64` and returns the range MINIMUM when fewer remain, so the length was **1**
  and the character index **0** — the composer saw the single character `-`, under
  `max_nodes = 1, max_depth = 1, reject_duplicate_keys = false`, every time. ⛔
  `fuzzAnchorAlias` was worse: its stated job is to GUARANTEE anchors, aliases and sometimes a
  cycle, because random bytes never spell `&a … *a` — and with `count`, the scalar index,
  `cyclic` and `aliased` all drawn from `smith`, it emitted `[&a0 42]` on every run. It
  guaranteed an anchor and nothing else; the alias-equality and `AliasCycle` oracles below it
  had never fired. Both now take one `smith.slice` call as their first draw — a real YAML
  document for the first, a reviewable script read with `testkit.fuzz.Cursor` for the second —
  with corpora lifted from the value tests. Measured: **composer 1 document (`-`) under 1
  budget → 19 of 20 seeds non-empty, 12 composed, 3 `AliasCycle`s, 13 distinct budgets;
  generator 1 distinct document, 0 aliases, 0 cycles → 7 distinct documents, 19 aliases, 2
  cycles.** The composer guard pins the node count, not just success, because `composeAll("")`
  legally succeeds as a stream of zero documents.
- **2026-08-18** — Portability fix (`check-portable`), test-only: "arbitrary input never
  panics" computed two fuzz bounds (`n = 1 + (s % buf.len)`, an alphabet index `(s >> 33)
  % alphabet.len`) as `u64` and used them to slice/index `buf`/`alphabet`, which fails to
  compile on a 32-bit target. Both moduli are always `< buf.len`/`< alphabet.len`
  (24/26-ish) regardless of `s`'s width, so the cast can never truncate a value that
  reaches it — an unconditionally-safe `@intCast`, not a real 64-bit quantity. Compile-only,
  identical semantics — no new test. Verified: `zig build portable-yaml` no longer errors
  on these two sites (the module still fails that gate via `testkit`'s
  `std.process.Environ` `[wasi-surface]` gap, pulled in through `suite_test.zig`,
  unrelated to this fix) and `zig build test-yaml --summary all` (47/47) is green.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on `libyaml`
  (the staging is explicitly modelled on it, `root.zig:70`); oracle is the
  **yaml-test-suite** (design reference, not a test anchor).
- **2026-07-30** — New module: YAML 1.2 reader (not 1.1) — scanner (tokens) → parser
  (events) → composer (native `Value`), tappable at either of the last two stages. Block
  sequences/mappings, all five scalar styles with their.

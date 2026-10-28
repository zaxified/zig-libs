# `regex` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-28** — **Faster:** `Matcher.captures` (and the iterator's `nextCaptures`) of a one-pass program — one where, read anchored, the next code point always picks at most one way on (`INV-([0-9]{4}-[0-9]{4})`, `(\w+)@(\w+)\.com`, `\b(\w+)\b`, `^(\d+)-(\d+)$`) — run on a one-pass engine (RE2's and Rust's): one thread whose captures are written in place, one table load per ASCII byte (the step packs the next root's row offset, the slots set and the assertions passed). The start comes as `find` gets it: from each candidate of a fast prefilter, read anchored by the engine itself; otherwise the DFAs' span, then the engine from its start. Made with the find DFA (after 1 KiB). Programs of up to 128 instructions and 16 groups; a match past an assertion is allowed when no way lies below it. `INV-([0-9]{4}-[0-9]{4})` captures over 85 KiB: 187 → 72 µs (3.2× → 1.35× Rust's `regex`, JCC-padded builds). Same groups (tested against the Pike VM on 26 patterns from every start, 7 planted analysis bugs all caught; the fuzz harness reaches it on ~9 % of its runs). `Matcher` gains the fields `onepass`, `onepass_tried` and the test switch `onepass_off`.

- **2026-10-28** — **Faster:** a `Matcher` makes its find DFA only once it has been handed 1 KiB of text to search (or one text that long): a fresh DFA works out every transition it takes, which over a short text cost more than the backtracker. A compile-and-find of 37 bytes is back from 1.8 µs to ~1.0–1.2 µs (what it was before the DFA). `Matcher` gains the field `vm_read` and the test switch `dfa_eager`.

- **2026-10-28** — **Faster:** when every match starts where a fast prefilter points (a literal prefix, one byte, Teddy), `find` reads forwards from each such place in turn, anchored, and the first one with a match is the leftmost-first match: no backward pass (RE2's search from a literal prefix). Tries that fail may read no more than twice the text they moved past (plus 256 bytes), then one unanchored pass takes over, so `A[^Z]*Z` over `AAAA…` stays linear. `INV-[0-9]{4}-[0-9]{4}` find-all over 85 KiB: 93 → 60 µs (1.6× → 1.05× Rust's `regex`, JCC-padded builds).

- **2026-10-28** — **Faster:** the literal search behind the prefilter tests two 32-byte blocks at a time. `ABC` find-all over 1 MiB of noise: 51–57 → 42–44 µs (1.5× → 1.05× Rust's `regex`, JCC-padded builds).

- **2026-10-28** — **Faster:** with no thread alive, the find DFA jumps ahead with the prefilter only when that is a fast scan (a literal, one byte, Teddy) or the next code point is past ASCII and cannot start a match; over short ASCII gaps it keeps reading its own cached transitions. The context assertions need comes from a byte table. JCC-padded builds, ours/Rust's `regex`: `[A-Z]+` 1.34 → 1.25×, `\p{L}+` 1.52 → 1.27×, `\b\w+\b` 1.76 → 1.26×, `[0-9]+` 1.56 → 1.23× (1 MiB each).

- **2026-10-28** — **Faster:** two-byte UTF-8 sequences are decoded inline (forwards and backwards; `std.unicode.utf8Decode` was a call, a quarter of a find-all over Czech text); the forward DFA's transitions hold the next state's row offset (no multiply between two lookups); the backward DFA's first state is remembered per context; the caches for code points past ASCII are made on the first such code point (a `Matcher` for one ASCII search does not pay for them). Find-all over 1 MiB of Czech, Greek and Cyrillic (JCC-padded builds): `\p{L}+` 16.3 → 9.9 ms (1.5× Rust's `regex`), `(?i)žluť\w*` 2.6 → 1.9 ms (1.1×); `INV-[0-9]{4}-[0-9]{4}` over 85 KiB 119 → 101 µs.

- **2026-10-28** — **Faster:** `Matcher.find` and the iterator (without captures) run every program of up to 128 instructions on the lazy DFAs, not only anchored ones: the forward one finds the end of the leftmost-first match (threads in priority order, a thread starting at every position until a match; with no thread alive it jumps ahead with the prefilter), a backward one from that end its start (the leftmost position from which the program reads exactly to the end). Both keep their transitions across calls, on ASCII bytes in a table, on other code points in a direct-mapped cache. Find-all over 1 MiB of Czech, Greek and Cyrillic: `\p{L}+` 2.7× → 2.3×, `\b\w+\b` 3.4× → 1.9×, `(?i)žluť\w*` 1.9× → 1.6×, `[0-9]+` 2.2× → 1.3× Rust's `regex`; `[A-Z]+` over 1 MiB of noise 2.2× → 1.3×. Same spans (tested against the Pike VM from every start, the fuzz harness on every pattern). A search starting inside a UTF-8 sequence keeps the VMs.

- **2026-10-28** — **Faster:** `Matcher.find` and the iterator (without captures) run a pattern anchored at the start (`^…`, `\A…`) on a lazy DFA kept in the `Matcher`: states are the Pike VM's thread lists in priority order, a match cuts the later ones (leftmost-first), and a transition on an ASCII byte is worked out once per `Matcher` (up to 256 states, then the table is emptied and refilled). `^[a-z]+` find-all over `hello world 123`: 115 → 60 ns (2.4× → 1.2× Rust's `regex`). Same spans (tested against the Pike VM, also past a full table; the fuzz harness checks every pattern's anchored twin `^(?:…)`). A `Matcher` that ran such a search holds the table until `deinit`.

- **2026-10-28** — **Faster:** short searches with positions. A pattern anchored at the start (`^…`, `\A…`) settles a search from any later position without running (an iterator's call after the first match); the backtracker pushes its pending branches without an out-of-line `append` and without building a tagged union on the stack (a failed store forward per push), and works out its bit budget per program once, at `Matcher.init`. `^[a-z]+` find-all over `hello world 123`: 182 → 115 ns (3.9× → 2.4× Rust's `regex`); `INV-([0-9]{4}-[0-9]{4})` captures over 85 KiB: 199 → 140 µs. No API change.

- **2026-10-27** — **Faster:** the literal-prefix walk behind Teddy tries a shorter cut when it runs out of its step or stack budget, instead of giving up (`(?i)[ab][cd]…[op]|zz` now gets two-byte prefixes). From the review of the Teddy commit; also a test that a class holding a surrogate never matches the bytes `ED A0 80`.

- **2026-10-27** — **Faster:** a pattern every match of which begins with one of a few literal prefixes and no common literal (`ABCD|CDEF|…|WXYZ`, `(?i)abc`, `foo\d|bar\d`) skips to the next place one of them occurs with Teddy (SIMD nibble tables over the first 2–3 bytes, up to 32 prefixes of up to 8 bytes; `src/teddy.zig`). Twelve four-letter alternatives over 1 MiB with no match: 5.4 ms → 0.12 ms (36× → 0.9× Rust's `regex`); `(?i)žluť\w*` find-all over 1 MiB of Czech: 5.2 → 2.9 ms. Same answers (tested against the program without the prefilter, the fuzz harness compares the two on every such pattern). `Prefilter` gains the field `teddy`.

- **2026-10-27** — **Faster:** before reading an end-anchored text backwards, `isMatch` compares its last bytes with those every match ends with (up to 16 ASCII code points, one or two bytes each: a literal suffix, or its cases under `(?i)`). A 1 MiB text ending in the last ten letters of `ABCDEFGHIJKLMNOPQRSTUVWXYZ$`: 1.2 µs → 11 ns.

- **2026-10-27** — **Faster:** `isMatch` of a pattern every match of which ends at the end of the text (`…$`, `…\z`, not also `^…`) reads the text backwards from its end with the lazy DFA, after a one-byte check that the text's last byte can end a match. Go's `regexp` benchmark shapes over 1 MiB (`easy0`, `easy1`, `medium`, `hard`, `icase`): 60 µs–3.2 ms → 4 ns; a text whose last ten bytes fit: 1.2 µs. Same answers (tested against the NFA and `Matcher.find`, fuzzed with a quarter of the patterns end-anchored).

- **2026-10-27** — **NO CONSUMER-VISIBLE CHANGE:** `bench-regex` also times Rust's `regex` 1.13.1 (`tools/rust_regex`, pinned `Cargo.lock`, built `--offline`) as the fastest candidate in the field; its result counts must agree too. Card: ref 0.03–0.72× Go, fastest 0.04–152258.86× Rust — end-anchored searches (`…$`) are the gap (Rust runs a reverse DFA from the end of the text).

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-19** — **Fix:** (audit S1) POSIX syntax allows a repetition of a repetition
  (`a**`, `a{2}{3}`), and such a chain adds neither instructions nor group depth, so nothing
  bounded it but the node table: `a{1}{1}{1}…` (~2000 times, 6 KB of pattern) made the
  recursive compiler overflow a 512 KiB thread stack — a crash from a pattern, not an error.
  `Builder` now budgets stacked repetitions per pattern (`max_stacked` = 64) and refuses the
  rest with `error.NestingDepth`. Perl syntax (which refuses `a**`) is unchanged.

- **2026-10-19** — FIX (wrong answers, no memory-safety impact): after a prefilter skip both
  NFA engines reused the closure's visited marks from the position where the last threads died,
  so an assertion that had failed there (`\b`, `^`, `$`) was never walked at the new position.
  `isMatch` answered false for programs over 128 instructions (the lazy DFA's limit, so
  `runSetOn` answered), e.g. `a?\b+(  *((xxxxa+)xx|()+){2}){1,3}` on `"a1 "` (reported by bxp's
  differential driver vs Go, 1 in ~20 M inputs). `find`/`captures`/the iterator missed matches
  wherever the Pike VM ran — every leftmost-longest (POSIX, `Longest`) search, and leftmost-first
  once the backtracker hands over — e.g. POSIX `(a?^[a-][^a])` on `" a \nabÉ"` (Go: [4 6]). The
  fuzz harness now pads a quarter of its patterns past the DFA's size with a dead alternative and
  half of those start `a?\b`-shaped; it finds the bug in ~3 s (it had never reached it).

- **2026-10-18** — Ported to Zig 0.17.0. `StaticBitSet` `.initEmpty()` becomes `.empty`; the vector-of-bool `@bitCast` in `findLiteral` is unchanged (bit i = lane i, verified by the existing tests).
- **2026-10-07** — Instrument: `tools/bench.zig` + `tools/go_bench/` (`zig build
  bench-regex`), the comparative benchmark against Go `regexp` behind the maturity
  card's `**Performance:**` line: 18 workloads, result counts checked against Go;
  0.02–0.91× Go's time (worst `sub_email`).
- **2026-10-07** — Faster, same answers, now ahead of Go 1.26 on every shared workload: `isMatch` /
  `fullMatch` run a lazy DFA on the stack (programs up to 128 instructions) — Go's Hard benchmark
  `[ -~]*ABC…$` over 1 MiB 16× faster than before (was 1.25× slower than Go, now 0.08), a 12-way
  alternation 12×; the bit-state backtracker covers a window of positions instead of refusing
  any text longer than its budget, so a short match in a long text no longer falls to the Pike VM
  — find-all with groups over 85 KiB 4.8× faster (1.30× slower than Go → 0.27), dense find-all
  over 1 MiB ~2×. No public API change; `isMatch`/`fullMatch` take ~4.7 KiB more stack (in a frame
  of their own, never live together with the NFA's).
- **2026-10-07** — Fixes from the audit of the entries below: a surrogate literal (`\x{D800}`, which Go
  compiles) panicked in the literal-prefix walk at compile time — now written as U+FFFD, as Go;
  `expand` with a repeated group name takes the first group of that name that took part (Go), not
  the first by index; a reader failing after the match was settled no longer turns it into
  `error.ReadFailed`; the backtracker hands a search to the Pike VM past 16 Ki pending jobs
  (was unbounded, ~12 MB worst case).
- **2026-10-07** — Faster, same answers: a bit-state backtracker (Go's and RE2's, one visited bit
  per position × instruction, ≤ 256 Kbit) finds matches with groups in short texts — submatches 4–11×
  faster than before, now ahead of Go; the literal prefix (up to 16 bytes) is searched for whole by
  a SIMD first-and-last-byte scan — `id=([0-9]+)` find-all 4.5× faster. New public fields
  `Prefilter.lit`/`lit_len`, `Matcher.bt_visited`/`bt_jobs`/`pike_only`; nothing breaks.
- **2026-10-07** — Reading from a `std.Io.Reader` (Go's `MatchReader`, `FindReaderIndex`,
  `FindReaderSubmatchIndex`): `Regex.isMatchReader`, `Matcher.findReader`,
  `Matcher.capturesReader` — constant memory, no allocator, `error.ReadFailed` from a failing
  reader. New public declarations only.
- **2026-10-07** — Go's API on top of a search: `Regex.expand` (`$1`, `${name}`, `$$`),
  `Matcher.replaceAll` / `replaceAllLiteral` / `replaceAllFunc` (to a `std.Io.Writer`) and
  `Regex.replaceAll` / `replaceAllLiteral` (allocating), `Matcher.split` (`SplitIterator`) and
  `Regex.split`, `quoteMeta` / `quoteMetaAlloc`, `Regex.literalPrefix`, `Regex.source` (Go's
  `String()`), `Iterator.nextCaptures` (FindAllSubmatchIndex), `matches` (MatchString). All
  against Go's answers. New public declarations only; nothing breaks.
- **2026-10-07** — Leftmost-longest matching (Go's `Longest()`): `Regex.longest`, or
  `Options.longest`. POSIX ERE syntax (Go's `CompilePOSIX`): `Regex.compilePosix`,
  `compileOptions(.., .{ .syntax = .posix })`, `comptimeCompileOptions`,
  `compileUsingOptions`, `validateSyntax`, `Builder.compileSyntax` — no Perl escapes or `(?…)`,
  `^`/`$` at line breaks, a negated class never matches `\n`, a repetition may repeat a
  repetition, leftmost-longest. New public: `Options`, `Syntax`; nothing breaks.
- **2026-10-07** — **BREAKING:** Unicode classes: `\pL`, `\p{Greek}`, `\PL`, `\p{^Name}`, inside
  `[…]` and under `(?i)` — every general category, its long alias (`\p{Letter}`) and script of
  Unicode 15.0, plus `Any`, `ASCII`, `Assigned`; names match loosely (case, spaces, `_`, `-`
  ignored), as Go 1.25+ documents. `error.UnsupportedUnicodeClass` is gone; an unknown name is
  `error.InvalidUnicodeClass`. Tables in `src/unicode_tables.zig` (generated by
  `tools/go_unicode`, 11 KB). A class written twice in one pattern is stored once.
- **2026-10-07** — `(?i)` folds by Unicode's simple case folding (Unicode 15.0, as Go 1.26):
  `(?i)é` matches `É`, `(?i)θ` all of `θ ϑ Θ ϴ`; before, only ASCII and K/ſ folded. New
  `src/casefold.zig` (generated by `tools/go_casefold`, Unicode License v3 in the new `NOTICE`);
  `interop-regex` re-takes it too. Faster, same answers: `Regex.compile` uses a stack builder
  (`BuilderOf(small_capacity)`) and falls back to the full one; no whole-table initialisation per
  compile or per `isMatch`; `Matcher.init` makes one allocation; a pattern anchored at `\A` is
  tried at the start only, and a first-byte prefilter skips ahead while no thread is alive. On a
  bxp-like per-row workload compile + match went from 44 µs to 0.48 µs per row, compile +
  captures from 45 µs to 0.80 µs. New public: `Regex.prefilter` (`Prefilter`), with a default;
  nothing breaks.
- **2026-10-07** — Tests: a fuzz harness (`src/fuzz_test.zig`, `testing.fuzz` + the deterministic
  driver `REGEX_FUZZ`), checked against planted mutants; `example/main.zig` (a log filter). No
  behaviour change.
- **2026-10-07** — Review fixes: nested counted repetitions multiply to at most 1000, as in Go
  (`(?:(?:a{0}){1000}){2}` is `error.InvalidRepeatSize`; before, such a pattern could make the
  compiler run ~10⁹ steps); `max_depth` 1000 → 250 so compiling fits a small thread stack;
  `a(?i)*` repeats `a`; `\` before a control character is a literal; `\x{…}` takes any number of
  hex digits and no sign or `_`; `Matcher.find`/`captures` past the input end find nothing.
- **2026-10-07** — Tests: mutation schemata run (34 mutants, 31 killed, 2 equivalent, 1 simplified
  away — `runeBefore` now reads only whether the byte before is ASCII, all the assertions look at);
  seven crafted oracle patterns added (a star over an assertion, `(?m)^` after an inner newline).
  No behaviour change.
- **2026-10-07** — `Regex.compileUsing(gpa, builder, pattern)`: `compile` with the caller's
  `Builder` (the ~70 KiB compile scratch), so many patterns compiled into an arena share one.
- **2026-10-07** — New module: RE2-syntax regular expressions (Go `regexp/syntax` grammar) on a
  Pike VM — linear time, leftmost-first, compiled without an allocator (also at comptime),
  `isMatch`/`fullMatch` without one, `Matcher` for submatches and non-overlapping iteration.
  Anchored on Go `regexp` as a differential oracle (791 patterns, 11,277 inputs). For `router`'s
  `{id:[0-9]+}` constraints.

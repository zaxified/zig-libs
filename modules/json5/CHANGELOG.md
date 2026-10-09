# json5 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — tests: deterministic fuzz driver `JSON5_FUZZ` over the existing harnesses.
- **2026-10-06** — **BEHAVIOURAL:** `preprocessAnnotated` no longer recovers a bad bare word (`nul`,
  `tru`) or a single-quoted string broken by a newline OUTSIDE an object (top level, or inside an
  array) — there is no sibling key to put the `$err` in, so it used to fix them silently: `nul` came
  out as the valid document `"nul"`, `{a: [tru]}` as `{"a": ["tru"]}`. Now the token goes out as
  written and `std.json` refuses the document, as `preprocess` and the reference json5 do (the
  double-quoted branch already behaved so). Anchoring: the reference oracle records where json5
  2.2.3 stops on each refused document; the editor mode must refuse too or report that line
  (`ref_oracle_test.zig`). Evidence MIXED → EXTERNAL.

- **2026-10-05** — Found by a new differential oracle against the reference `json5` package
  (`tools/ref_oracle.js`, replayed by `src/ref_oracle_test.zig`, 2672 generated documents):
  - **Fix:** JSON5 string escapes JSON lacks (`\v`, `\0`, `\xHH`, `\q`-style NonEscapeCharacters,
    `\é`, `\'` inside double quotes) are rewritten to their characters; they were copied and
    `std.json` refused the valid document.
  - **Fix:** unquoted keys take non-ASCII code points and `\uXXXX` escapes (`{é: 1}`, `{a\u0062: 1}`,
    ZWNJ/ZWJ, combining marks), and a comment between a key and its `:` (`{a /* c */: 1}`); both went
    into `$err_trace` recovery.
  - **BEHAVIOURAL:** a truncated document (`{"servers": [{"host": "a"}`) is no longer completed at
    EOF: containers are auto-closed only after a recovery in the same run. Before, a config cut off
    mid-write parsed as a valid one with fewer entries. Both entry points.
  - **Fix:** a dropped `+` no longer joins two numbers (`1+2` was `12`, `1.+3` `13`).

- **2026-10-04** — Fix: raw control characters (U+0000..U+001F other than LF/CR, e.g. a TAB)
  inside a `"…"` or `'…'` string are valid JSON5 (JSON5 §5) but were copied through unescaped,
  so `std.json` refused the document; both entry points now emit `\t`/`\b`/`\f`/`\u00XX` (also
  for `\` + such a character, a JSON5 NonEscapeCharacter). Inputs that were refused are now
  accepted; output of every previously accepted input is unchanged.
- **2026-10-04** — Fix: `preprocess` treated LF, CR, U+2028 or U+2029 between an unquoted key and
  its `:` as the end of the key and replaced the member with an `$err_trace` diagnostic; JSON5 §6
  makes them whitespace, as `preprocessAnnotated` already did. `{a\n: 1}` is now `{"a": 1}`.
- **2026-10-04** — **Tests:** mutation run (52 schemata mutants, 51 killed, 1 equivalent). New
  tests for both fixes, an inner `"` in a single-quoted string, zero-padded hex limbs
  (`0x3B9ACA00`), error recovery keeping every sibling key across strings, escapes, apostrophes
  and nested values on both entry points, and the 30-character diagnostic fragment cap.

- **2026-09-30** — **JSON5 numeric literals, string line continuations and JSON5 whitespace**
  (survey items; scope raised from mvp to core). Both entry points now rewrite into plain JSON:
  hex `0x1A`/`-0xff`/`0X1a` → the exact decimal integer (any value up to
  `hex_digits_max` = 256 significant hex digits; longer is `error.HexLiteralTooLarge`, passed through
  verbatim by the annotated entry), `.5` → `0.5`, `5.` → `5`, `5.e2` → `5e2`, `+1` → `1`; backslash +
  LF/CR/CRLF/U+2028/U+2029 inside a string is removed; form feed, vertical tab, NBSP, BOM,
  U+2028/2029 and the Unicode Zs spaces between tokens become one space, and U+2028/2029 end a `//`
  comment. Malformed numbers (`01`, `0x`, `0x1.5`, `1.2.3`) pass through whole so `std.json`
  rejects them and no fragment is re-scanned as a second number. Nothing inside strings, comments
  or keys is touched. **`Infinity`/`-Infinity`/`+Infinity`/`NaN`: an error by default**
  (`error.NonFiniteNumber`, plus `Options.diagnostic` with line and message); opt-in
  `Options{ .non_finite = .quoted }` rewrites them to the strings `"Infinity"`/`"-Infinity"`/`"NaN"`
  (never `null`), which `std.json` reads into an `f64` as `inf`/`nan`. New API:
  `preprocessWithOptions`, `preprocessAnnotatedWithOptions`, `Options`, `NonFinite`, `Diagnostic`,
  `hex_digits_max`; `preprocess`/`preprocessAnnotated` keep their signatures but `preprocess` can now
  return the two new errors. Corpus: 37 → 5 out-of-scope fixtures (only the `Infinity`/`NaN` ones,
  asserted by a test of their own).
- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/json5_tests_vectors.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-09-07** — **Three recovery defects, found by the first corpus that ever
  reached this module's fuzz harnesses.** Both targets opened with
  `smith.bytes(&buf)` followed by `smith.valueRangeAtMost(u16, 0, buf.len)`;
  `bytes` consumes `min(buf.len, in.len)` octets and the ranged draw then reads
  eight *more* as a little-endian u64, returning the range minimum when fewer
  remain — so the drawn length was 0 for every input a seed can carry, and with no
  corpus either each target replayed one empty document for ever. That mattered
  more here than elsewhere: `fuzzPreprocessAnnotated` exists for a differential
  ORACLE — the two entry points must agree on whether the result parses — and on
  the empty input they trivially agree, so the oracle had never once compared two
  outputs that could differ. Given a 22-seed corpus it failed immediately, three
  times:
  - **`preprocess` did not close containers the input left open.** `preprocess("{a b")`
    emitted `{"$err_trace_1": "a b --> missing colon after key at line 1"` with no
    `}`, so the recovery entry it had just built sat in a document `std.json`
    cannot read. `preprocessAnnotated` has auto-closed at EOF all along. ⭐ `{a b`
    is this module's OWN audit-F1 crash reproducer and its test only asserted that
    the string `$err_trace` appears in the output — never that the output parses.
    `preprocess` now auto-closes, and the test now parses its result.
  - **`preprocessAnnotated` closed an unterminated string at EOF even outside an
    object**, where there is nowhere to record a diagnostic: `"unterminated` came
    out as the valid document `"unterminated"`, with no error anywhere. That is
    exactly the failure the W2 re-audit's F2 fix removed from the NEWLINE branch
    ("with nowhere to report, the honest move is not to recover") — the EOF branch
    kept it. Now guarded the same way.
  - **`preprocess` closed an unterminated SINGLE-quoted string unconditionally**:
    `'unterminated` became the valid `"unterminated"`, while the double-quoted
    branch six lines above left `"unterminated` open. Same class, same fix; the
    two string kinds had also disagreed with each other.
  Harnesses now draw with one `smith.slice(&buf)` and share a 22-seed corpus, so
  the oracle compares both entry points on the same input. Guard pins octets
  emitted and documents rewritten rather than acceptance, because `preprocess("")`
  succeeds: measured 0 / 0 / 0 before; 22 seeds, 646 octets, 18 rewritten,
  4 carrying a diagnostic after.
- **2026-09-02** — Drift re-audit (W2, window `0575340..HEAD`). Ten findings, all fixed:

  - **CRITICAL, silent corruption of valid input:** the bare-identifier branch fired on the `e`
    of an exponent, so `preprocessAnnotated` split every number in exponent notation and quoted
    the tail — `{"a": 1e10}`, plain RFC 8259 JSON, came out as
    `{"a": 1"e10", "$err_1": …}`, which is not JSON at all. Eight must-parse fixtures already
    vendored in this repo exercised it, and none of them ran against this entry point.
    Numeric literals are now consumed as one token.
  - **O(n²) removed, twice.** `lineOf` rescanned from byte 0 for every recovered error, and
    `preprocess`'s colon scan ran to end of input for every malformed key. 1 MB of `{a b,…}` took
    123 s through `preprocess` and 61 s through `preprocessAnnotated`, against 11 ms for a
    well-formed file of the same size. Both walks are forward-only now (512 KB: 31.8 s → 7.5 s,
    and 4.0–4.1× per 4× of input from 16 KB up). The bounded colon scan also stops `preprocess`
    absorbing a later key's colon, which used to swallow siblings and drop the closing brace.
  - **`skipValue` treated `'` and `"` as interchangeable**, so an apostrophe inside a
    double-quoted value closed it and the scan ran to EOF: `{a b: "don't", c: 2, d: 3}` lost the
    keys `c` and `d` into a diagnostic string. It now closes only on the quote that opened.
  - **A block comment separates tokens.** Its bytes were deleted with nothing put in their place,
    so `[1/*c*/2]` became `[12]` — a must-reject input turned into a valid document with a
    fabricated value. `preprocessAnnotated` also never got `preprocess`'s unterminated-comment
    fix and leaked the comment's last byte back into the document.
  - **A key this module cannot spell no longer corrupts the document around it.** A
    non-identifier byte in key position was copied out with `key_pos` still set, landing *ahead*
    of the `"$err_…":` that followed: `{été: 1, b: 2}` emitted `{é"$err_1": …}` and lost the
    sibling `b`. Such keys route into recovery like every other unspellable key.
  - **The diagnostic key namespace is reserved against the input.** `$err_<N>` had a predictable
    name and a counter starting at 1, and the input was never consulted: a colliding key in the
    source hid the real diagnostic under `.use_last`, or turned any recovered error into
    `error.DuplicateField` under `std.json`'s default. The prefix now carries one more underscore
    than the longest run already present — collision-free by construction.
  - `Infinity`/`NaN` pass through for `std.json` to reject, like every other deferred construct.
    Quoting them did not defer them: it fabricated the *string* `"Infinity"` where a number
    belonged, and made a document parse that `preprocess` rejects.
  - An unterminated string outside an object is no longer "recovered". A `$err_<N>` can only be a
    sibling key inside an object, so outside one the recovery closed the string, dropped the rest
    and reported **nothing**: the must-reject `"foo\nbar"` became the document `"foo"`.
  - Every fragment quoted into a diagnostic is capped. The value was capped at 30 characters "so
    the message stays compact in the GUI"; the raw key and the no-colon tail were not, so a
    200 KB key produced a 200 KB "compact" message.
  - **Docs, and the tests behind them.** SPEC and README claimed `preprocessAnnotated`'s output
    is *always* valid JSON. It is not and cannot be — empty input, and every deferred JSON5
    construct, are passed to `std.json` to reject on purpose — and the claim hid real defects: 63
    of the 112 vendored fixtures failed it. The corpus drove `preprocess` only, leaving the entry
    point the source calls "the most intricate state machine in the module" with zero corpus
    coverage, and the fuzz target guarding it asserted only "does not panic", which is
    `preprocess`'s contract. Both now assert the guarantee that is true and that a caller relies
    on: **turning diagnostics on does not change whether the document parses.**
  - `objects/illegal-unquoted-key-number.txt` joins the known-disagreement list. It used to
    reject "correctly" — by the wrong route: what broke the object structure was the
    non-identifier-key defect above, and the corpus read that as a rejection.

- **2026-07-19** — Security audit: a CRIT/HIGH finding was fixed (part of the
  collection-wide audit; the root changelog records no further detail
  than this).

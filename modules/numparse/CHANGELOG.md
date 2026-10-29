# numparse — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-29** — **NO CONSUMER-VISIBLE CHANGE:** Delta audit of the no-panic sweep: the sweep changed tests only; no mutants, the review date moves. Card A1 again.
- **2026-10-29** — **NO CONSUMER-VISIBLE CHANGE:** no-panic sweep found no defect; two tests pin empty, 1 MiB and hostile input across the option grid and the range of every CLDR row's native index.
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the all-module `strRepeat` rewrite (`571bf09e`) is reverted here: this module's calls are small (seconds of Sema at most), and the change would have made its fresh audit's `src` hash stale for nothing.

- **2026-10-23** — **Card: grade 1** (S1 E1 A1 P1). Speed: 0.11× ICU4C's `DecimalFormat::parse`
  (`bench-numparse` now also times the system ICU, `tools/icu_bench`; ICU and Babel agree with us on
  every line), a Babel defect (strict refuses correctly grouped native digits), accounting negatives
  and percent. Audit: independent review (no defect) + 33 mutants (30 killed, 3 equivalent).
  **Docs/tests only:** `percent` is ASCII `%` and comes off before a trailing minus (`5-%` is
  -0.05), tests for empty bodies and malformed UTF-8, the table generator asserts what `parse`
  assumes of every row. No behaviour change.
- **2026-10-20** — `zig build bench-numparse` (`tools/bench.zig` + `tools/bench_ref.py`, Babel 2.17 under python 3.14): 0.007–0.04× the reference. Card: grade 3 → 2 (scope parity, P2).
- **2026-10-20** — Every CLDR locale and native digits (S2). `locale(name)` reads a generated table of
  Babel 2.17's 1066 locales (`src/cldr_locales.zig`, `tools/babel-oracle.py --gen-table`; ASCII
  case-insensitive, `-` = `_`); `Grouping` gains `.two` (tok) and `.none` (en_US_POSIX);
  `localeNative(name)` gives the locale's own numbering system's symbols and digits, and `Options.zero`
  makes the scanner read the ten digits from that code point (ASCII unchanged by default). Goldens
  5 452 → 11 092 Babel cases over 171 locale tags. NOTICE: CLDR data (Unicode License V3). The 25 old
  rows answer as before. **Source-breaking** only for an exhaustive `switch` over `Grouping`.
- **2026-10-18** — Ported to Zig 0.17.0. comptime `strRepeat` helper: larger `@setEvalBranchQuota` (0.17 counts more branches per iteration).
- **2026-10-04** — **mvp → core.** New `parse(s, Options) ?Decimal` with `Options`, `Grouping` and
  `locale(name)` (CLDR group/decimal/grouping for 25 locales): UTF-8 separators (U+00A0, U+202F,
  `’`), Indian lakh/crore grouping, `+` and U+2212, parenthesised and trailing-minus negatives,
  exponent on ungrouped numbers, percent, `lenient_spaces`, optional `require_grouping`. Checked
  against Babel's strict `parse_decimal` on 5 452 cases (`tools/babel-oracle.py`, golden kept);
  mutation 19 mutants, 0 surviving (1 equivalent, 1 redundant check removed). The table check
  caught a wrong `de_AT` row (CLDR groups with `.`). `parseGroupedNumber` is unchanged.

- **2026-07-18** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on ICU `NumberFormat` parse
  (design reference, not a test anchor).
- **2026-07-09** — New module: Locale-aware grouped-number parsing (thousands/decimal
  separators) into an exact `decimal.Decimal`.

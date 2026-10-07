# `regex` verification instruments

One oracle and one table generator; their output is frozen in `src/go_vectors.zig` (replayed by
`src/go_oracle_test.zig`) and `src/casefold.zig` (compiled into the module), used with no Go in
the module's own lane (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-regex`: runs `go_regexp_oracle` and writes (or with `--check` compares) the vectors. The interop lane runs it with `--check`. |
| `go_casefold/` | Go's `unicode.SimpleFold` (Unicode 15.0 in Go 1.26) over every code point → `src/casefold.zig`: the simple case-folding orbits as 366 runs. The generator re-checks its runs against `SimpleFold` for all 1,114,112 code points before writing. Standard library only. |
| `go_unicode/` | Go's `unicode` (Unicode 15.0 in Go 1.26): `Categories`, `CategoryAliases`, `Scripts` over every code point → `src/unicode_tables.zig`: the 30 two-letter categories and 163 scripts as varint ranges, every other name as a list of those — each checked against Go's own table for every code point before writing. Standard library only. |
| `go_regexp_oracle/` | Go's `regexp` (BSD-3-Clause, the module's reference) as a black box through its public API: ~200 crafted syntax cases (the compile verdict, and matches over 21 fixed inputs) and 600 seeded random patterns × 14 random inputs; per input `MatchString`, a full match (the parsed pattern wrapped in `\A…\z`), `FindStringSubmatchIndex` and `FindAllStringIndex`. Standard library only. No Go source read. |

```bash
zig build interop-regex              # re-take, write src/go_vectors.zig
zig build interop-regex -- --check   # re-take, compare with the committed file
```

Needs Go 1.26.0 and `zig` on PATH.

**What the replay holds** (2026-10-07): ~1,800 patterns, ~31,000 inputs answered as Go answers —
compile verdict, group names, match, full match, every submatch index, every non-overlapping
match, the same after `Longest()`, the POSIX sets as `CompilePOSIX`, every case again through a
one-byte-per-read reader; for 460 patterns also ReplaceAllString (31 templates), the Literal and
Func forms, Split (all and limited), FindAllStringSubmatchIndex and LiteralPrefix; QuoteMeta of
every ASCII byte. Listed divergences, pinned: GO_DEFECT — Go 1.26 refuses 46 script names it
documents (46 patterns); LITERAL_PREFIX — ours extends Go's through agreeing branches (5);
CAPACITY — past 1024 instructions or nesting past 250 (5). Teeth: the first run found four
defects (an unanchored search that stopped at the first position with no thread, case folding
applied after negating `\W`/`[:^alpha:]` instead of before, the empty pass of `x*` over an
empty-matching `x` lost, and three grammar differences — `\ `, `(?)`, duplicate group names);
planted bugs since: a reader that leaves continuation bytes (1,541 cases fail), swapped
backtracker branches.

# `regex` verification instruments

One oracle and one table generator; their output is frozen in `src/go_vectors.zig` (replayed by
`src/go_oracle_test.zig`) and `src/casefold.zig` (compiled into the module), used with no Go in
the module's own lane (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-regex`: runs `go_regexp_oracle` and writes (or with `--check` compares) the vectors. The interop lane runs it with `--check`. |
| `go_casefold/` | Go's `unicode.SimpleFold` (Unicode 15.0 in Go 1.26) over every code point → `src/casefold.zig`: the simple case-folding orbits as 366 runs. The generator re-checks its runs against `SimpleFold` for all 1,114,112 code points before writing. Standard library only. |
| `go_regexp_oracle/` | Go's `regexp` (BSD-3-Clause, the module's reference) as a black box through its public API: ~200 crafted syntax cases (the compile verdict, and matches over 21 fixed inputs) and 600 seeded random patterns × 14 random inputs; per input `MatchString`, a full match (the parsed pattern wrapped in `\A…\z`), `FindStringSubmatchIndex` and `FindAllStringIndex`. Standard library only. No Go source read. |

```bash
zig build interop-regex              # re-take, write src/go_vectors.zig
zig build interop-regex -- --check   # re-take, compare with the committed file
```

Needs Go 1.26.0 and `zig` on PATH.

**What the replay holds** (2026-10-07): 850 patterns, 16,455 inputs (5,572 matching) answered as
Go answers — compile verdict, group names, match, full match, every submatch index, every
non-overlapping match. Listed divergences, pinned: UNICODE_CLASS — `\pL`, `\p{Greek}`, `\PL` compile
in Go and are `error.UnsupportedUnicodeClass` here (3 patterns); CAPACITY — a program past 1024
instructions or nesting past 250 compiles in Go and is refused here (4 patterns). Teeth: the first run found four
defects (an unanchored search that stopped at the first position with no thread, case folding
applied after negating `\W`/`[:^alpha:]` instead of before, the empty pass of `x*` over an
empty-matching `x` lost, and three grammar differences — `\ `, `(?)`, duplicate group names).

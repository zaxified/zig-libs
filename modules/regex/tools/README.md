# `regex` verification instruments

One oracle; its answers are frozen in `src/go_vectors.zig` and replayed by
`src/go_oracle_test.zig` in the module's own lane, with no Go (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-regex`: runs `go_regexp_oracle` and writes (or with `--check` compares) the vectors. The interop lane runs it with `--check`. |
| `go_regexp_oracle/` | Go's `regexp` (BSD-3-Clause, the module's reference) as a black box through its public API: ~200 crafted syntax cases (the compile verdict, and matches over 21 fixed inputs) and 600 seeded random patterns × 14 random inputs; per input `MatchString`, a full match (the parsed pattern wrapped in `\A…\z`), `FindStringSubmatchIndex` and `FindAllStringIndex`. Standard library only. No Go source read. |

```bash
zig build interop-regex              # re-take, write src/go_vectors.zig
zig build interop-regex -- --check   # re-take, compare with the committed file
```

Needs Go 1.26.0 and `zig` on PATH.

**What the replay holds** (2026-10-07): 827 patterns, 11,676 inputs (4,169 matching) answered as
Go answers — compile verdict, group names, match, full match, every submatch index, every
non-overlapping match. Listed divergences, pinned: UNICODE_CLASS — `\pL`, `\p{Greek}`, `\PL` compile
in Go and are `error.UnsupportedUnicodeClass` here (3 patterns); CAPACITY — a program past 1024
instructions or nesting past 250 compiles in Go and is refused here (4 patterns). Teeth: the first run found four
defects (an unanchored search that stopped at the first position with no thread, case folding
applied after negating `\W`/`[:^alpha:]` instead of before, the empty pass of `x*` over an
empty-matching `x` lost, and three grammar differences — `\ `, `(?)`, duplicate group names).

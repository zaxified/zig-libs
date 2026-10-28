# `regex` verification instruments

Two oracles and one table generator; their output is frozen in `src/go_vectors.zig` and
`src/rust_vectors.zig` (replayed by `src/go_oracle_test.zig` and `src/rust_oracle_test.zig`) and in
`src/unicode16_tables.zig` + `src/casefold16.zig` (compiled into the module), used with no Go or
Rust in the module's own lane (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-regex`: runs `go_regexp_oracle`, `rust_regex_oracle` and `rust_unicode` and writes (or with `--check` compares) their files. The interop lane runs it with `--check`. |
| `rust_unicode/` | Rust `regex-syntax` 0.8.11 (Unicode 16.0; the crate behind `regex` 1.13.1, pinned `Cargo.lock`, one crate, no build script) as a black box: every `\p{…}` query it resolves (bare names, `gc`/`sc`/`scx`/`age`/`gcb`/`wb`/`sb` by value, binary properties, `\w \s \d`) and its simple case folding `(?i)[\x{C}]` over every code point → `src/unicode16_tables.zig` (440 varint tables, 1,413 keys, each checked against the crate for every code point) and `src/casefold16.zig` (379 runs). Only the crate's alias lists are scanned as data (crate dir on the command line). Run: `cargo build --release --offline` in the tool dir, then `target/release/rust_unicode --crate ~/.cargo/registry/src/*/regex-syntax-0.8.11 -out ../../src` (or `-check ../../src`); needs `zig` on PATH and `src/unicode_tables.zig` (the `go` flags). |
| `bench.zig` + `go_bench/` + `rust_regex/` | `zig build bench-regex [-- <name filter>]`: comparative benchmark against Go's `regexp` and Rust's `regex` 1.13.1 (the fastest candidate; pinned `Cargo.lock`, five crates, all `build = false`, no proc macros — read 2026-10-27; built `--offline`, Go's ASCII `\d \w \s \b` rewritten to the crate's `(?-u:…)`), the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). 19 workloads over generated texts (1 MiB printable noise, the same ending in `QRSTUVWXYZ`, ~85 KiB invoice lines, 1 MiB Czech/Greek/Cyrillic) and short strings; both sides double the batch until it takes 100 ms and keep the best of five; result counts must agree or the run fails. Prints the worst ratio against each. Not run by any lane. 2026-10-27, x86-64, after Teddy: Go 0.00–0.79, Rust 0.04–4.1 (worst `anch_all`, then the searches with positions 2.1–3.0; `hard1` 36 → 0.87). |
| `go_regexp_oracle/` | Go's `regexp` (BSD-3-Clause, the module's reference) as a black box through its public API: ~200 crafted syntax cases (the compile verdict, and matches over 21 fixed inputs) and 600 seeded random patterns × 14 random inputs; per input `MatchString`, a full match (the parsed pattern wrapped in `\A…\z`), `FindStringSubmatchIndex` and `FindAllStringIndex`. Standard library only. No Go source read. |
| `rust_regex_oracle/` | Rust `regex` 1.13.1 (Unicode 16.0; pinned `Cargo.lock`, the same five reviewed crates as `rust_regex/`, no build script) as a black box through its public API, for `Options.syntax = .rust`, `Options.utf8 = false` and `RegexSet` → `src/rust_vectors.zig`: ~1,450 crafted Rust-syntax cases (flags `i m s R U u x` and their scoping, `(?x)` whitespace/comments, `\b{start}` & co, escape forms, class set operations, nesting/size limits, capture names, refused look-around and back-references) and ~320 Unicode property names (categories, scripts, `scx`, binary properties) over a handful of code points, 600 seeded random patterns × 14 inputs, ~420 crafted + 200 random `regex::bytes` patterns over inputs with invalid UTF-8, and ~90 `RegexSet`s. Per input: `is_match`, a full match (`\A(?:re)\z`), `captures_read` positions, `find_iter` spans, `shortest_match`; per pattern the compile verdict (no error texts) and `capture_names`. Std + `regex` only; own splitmix64 PRNG. Run: `cargo build --release --offline` in the tool dir, then `target/release/rust_regex_oracle -out ../../src/rust_vectors.zig` (or `-check ../../src/rust_vectors.zig`); needs `zig` on PATH. |

```bash
zig build interop-regex              # re-take, rewrite the generated files
zig build interop-regex -- --check   # re-take, compare with the committed files
```

Needs Go 1.26.0, cargo (offline, the pinned crates in its registry) and `zig` on PATH.

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

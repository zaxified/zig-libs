# Quality Tooling for Zig

Coverage, dead code, duplication, linting and fuzzing. Zig ships none of these,
and the usual third-party answers each have a trap that silently produces a
green result. The measurements below were made against Zig `0.17.0-dev.1158` on
macOS (aarch64) and cross-checked on Linux targets; the std APIs shown (the
fuzzer in particular) exist in the released 0.16.0 as written.

## Quick Reference

| Want | Tool | The trap |
|------|------|----------|
| Line coverage | `kcov` on the test binary | tests share the file with the code, so they inflate the ratio |
| Unused constants | `zlint` (`unused-decls`, on by default) | the Homebrew `zlint` is a *certificate* linter |
| Unused **functions** | nothing — roll your own | compiler is lazy, `unused-decls` skips functions |
| Duplicate code | `jscpd --format c --formats-exts "c:zig"` | `--max-lines 1000` silently skips bigger files |
| Fuzzing | `std.testing.fuzz` + `zig build test --fuzz` | `testOne` takes `*Smith`, not `[]const u8` |

## The denominator problem (affects coverage *and* lint)

Zig unit tests normally live in the same file as the code they exercise —
that is the only way to reach private declarations. So "exclude the tests"
cannot be a file filter; it has to be a line range.

Measured on a real library: **99.7% over 1325 lines** with tests counted,
**99.5% over 382** without. The denominator differed by 3.5×, so the flattering
number was mostly tests covering themselves.

Convention that works: a banner line (`// --- tests ---`) marks where
scaffolding starts; post-process the report and drop anything at or below it.

## Coverage: kcov

Works on Zig binaries with no instrumentation, on macOS as well as Linux.

```bash
zig test src/lib.zig -lc -femit-bin=.cov/testbin --test-no-exec
kcov --include-pattern=src/ .cov/report .cov/testbin
```

Read `.cov/report/<binary>.<hash>/codecov.json` for **per-line** data — the
`coverage.json` sibling only has file-level summaries. Values are strings of
the form `"taken/total"` over a line's sub-conditions, so a line executed at
all iff the numerator is non-zero:

```python
taken = int(value.split("/", 1)[0])   # "0/4" -> never ran; "1/2" -> ran, one branch
```

Prefer this over the cobertura `cov.xml`: same data, no XML parser, no XXE
surface.

**What will never be covered** without syscall failure injection: `errdefer`
bodies (they need the constructor to fail after acquiring the resource) and
`EINTR` retry branches. Accept them or mock the syscall; do not contort the
code.

## Dead code: nothing finds unused functions

Three layers all miss it:

1. **The compiler.** Zig analyses lazily — an unreferenced private declaration
   is never analysed, so it compiles fine and warns about nothing.
2. **`zlint`'s `unused-decls`.** Enabled by default, but it covers constants
   and variables only. Verified by planting one of each: the `const` was
   reported, the `fn` was not, and `zig build test` stayed green.
3. **`pub`** is API surface, so it is correctly never reported.

Why not just fix zlint? Resolving `handler.onRecord(rec)` where
`handler: anytype` requires knowing the receiver's type, i.e. monomorphisation
— reimplementing a large part of the compiler. Same for `@field(T, name)`,
`std.meta.declarations` and `refAllDecls`, which reference by computed name.

### Technique 1 — rename probe (exact, N builds)

Rename each private definition and rebuild. If every call site still resolves,
nothing referenced it.

```python
line = line.replace(f"fn {name}(", f"fn {name}__probe(", 1)
# write, run `zig build test`, restore in a finally
```

Exact. Cost is one build per function (~14s for 24 functions with a warm
cache). Blind spot: a *recursive* dead function looks used, because renaming
breaks its own recursive call.

### Technique 2 — syntactic prefilter (instant, misses some)

A private function whose identifier occurs exactly once in the file — at its
own definition — is dead.

```python
len(re.findall(r"\b" + re.escape(name) + r"\b", source)) <= 1
```

**Errs only by missing.** A call spells the name out, so `x.foo()` counts as a
reference whether or not the receiver's type is known — `anytype` and generics
cannot make it accuse a live function. It does miss a dead `end` or `add` when
a live method shares that name. 0.2s vs 14s; use it as a prefilter (skip the
build for anything it already proves dead) and as a pre-commit hook.

### Technique 3 — symbol table (one build, unreliable)

Since unreferenced decls are never analysed, they emit no symbol:

```bash
zig test src/lib.zig -lc -femit-bin=tb --test-no-exec
llvm-nm tb | grep '_mymodule\.'      # symbols are _<module>.<container>.<fn>
```

Measured false-positive rate: **4 of 22** private functions had no symbol
despite being live (small ones get inlined even in Debug). Fine as a hint,
wrong as a gate.

Linker GC (`-ffunction-sections` + `--gc-sections`, `-dead_strip` on Darwin)
has the same inlining problem.

## Duplicate code: jscpd

No Zig tokenizer exists, but the C one is close enough:

```bash
jscpd src --format c --formats-exts "c:zig" --min-lines 5 --min-tokens 40 \
      --max-lines 100000
```

**`--max-lines` defaults to 1000 and skips longer files without saying so.**
A first run reported "0 clones" having silently analysed only the one small
file in the project. Always pass it, and sanity-check "Files analyzed" against
the real count.

## Linting: zlint

⚠️ **Name collision.** The Homebrew `zlint` is [zmap/zlint](https://github.com/zmap/zlint),
an X.509 certificate linter. It accepts `.zig` paths and reports nothing
useful. The Zig one is [DonIsaac/zlint](https://github.com/DonIsaac/zlint) —
install the release binary; it is not in Homebrew.

```bash
zlint                    # default rule set
zlint -f json            # one JSON object per finding, concatenated (no commas)
zlint --deny-warnings    # warnings become a non-zero exit
zlint --print-ast f.zig  # it uses std.zig.Ast, so tree-sitter adds nothing
```

Parsing JSON output needs `raw_decode` in a loop — the objects are
concatenated, not an array.

**Config replaces the rule set, it does not extend it.** A `zlint.json`
listing one rule silently switches every other rule off. Verified: 14 warnings
became 0. Prefer no config unless you list everything you want.

Silencing:
- `unsafe-undefined` — accepts a `// SAFETY: <reason>` comment on the line
  above, or wants the `undefined` moved out of a struct-field default.
- `suppressed-errors` (`catch {}`) — a comment does **not** silence it.
  Handle the error or accept the warning.

## Fuzzing: the built-in fuzzer

### Signature changed — `*Smith`, not `[]const u8`

```zig
test "fuzz parsePacket" {
    try std.testing.fuzz({}, fuzzOne, .{});
}

fn fuzzOne(_: void, smith: *std.testing.Smith) !void {
    var buf: [2048]u8 = undefined;
    const n = smith.slice(&buf);          // returns the length written
    _ = parsePacket(buf[0..n], &handler);
}
```

`Smith` generates values, not raw bytes: `smith.value(T)`,
`smith.valueRangeAtMost(T, lo, hi)`, `smith.slice(buf)`,
`smith.eosWeightedSimple(a, b)` (each has a `...WithHash` variant taking an
explicit call-site hash). `FuzzInputOptions` is `.{ .corpus = &.{...} }`.
`slice` reads a 4-byte length before the bytes, so a raw corpus seed loses its
first four bytes; see [zig-016-gotchas.md](zig-016-gotchas.md).

**A doc comment cannot be attached to a `test`** — `///` above it is a compile
error. Use `//`.

### Running it

```bash
zig build test --fuzz=200000   # bounded, prints a report
zig build test --fuzz          # unbounded + web UI showing covered lines
```

A plain `zig build test` runs the fuzz test once with a trivial input, so it
costs nothing in the normal suite.

### The corpus is the asset — and it compounds

Coverage guidance only pays off through the persisted corpus in `.zig-cache/f/`.
Demonstrated by asserting "no generated input ever parses a record" and seeing
whether the fuzzer could break it:

| corpus | runs | broke the assertion? |
|--------|------|----------------------|
| empty | 400,764 | **no** |
| accumulated (1,152 unique inputs) | **5** | yes |

From scratch it is no better than blind random mutation. Which also means:

**Coverage plateaus if the harness feeds raw bytes.** Over 30M total runs,
coverage stalled at 75 edges after the first ~600k; a further 10M runs added
22 unique inputs and zero new coverage. Structure the harness (build the
header and records *from* Smith values) or seed `.corpus` with valid inputs —
running longer does not help.

### Two fuzzers, one corpus

```
thread N panic: corpus of '<test name>' is in use by another fuzzer
```

Concurrent runs abort, and the abort leaves a `.zig-cache/f/crash` artifact
that is **not** a real finding. Check the panic message before treating a
`crash` file as a bug.

## Hand-rolled fuzzing still earns its place

Blind mutation of a *valid seed input* reaches deep paths immediately, because
the structure is supplied by hand. On a DNS parser: 200k fully random buffers
parsed **0** records; 200k mutations of a valid packet parsed 415,869. It is
deterministic (fixed PRNG seed) so it works as a regression test, where the
coverage-guided fuzzer explores. Keep both.

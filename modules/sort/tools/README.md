# sort — tools

Kept instruments (CONVENTIONS.md §9, kind 3).

| File | What it is | Needs | Produces |
|---|---|---|---|
| `bench.zig` | `zig build bench-sort`: ours vs Rust std (reference) vs C++ libstdc++ over 31 workloads (unstable, stable, select; `u64`/`u32`/32-byte record/string; random, 16 distinct, ascending, descending, saw, sorted with a random tail; 1k–1M) | `cargo`, `g++` | the card's `**Performance:**` line |
| `rust_bench/` | the reference side: Rust std `sort_unstable` / `sort` / `select_nth_unstable`, std only (no crates), built `-C target-cpu=native` | `cargo` (offline) | one row per run |
| `cpp_bench/main.cpp` | the second side: `std::sort` / `std::stable_sort` / `std::nth_element` | `g++` | one row per run |

All three sides generate the same inputs from the same seed (bench.zig's
header specifies the generator) and must agree on a sampled checksum of the
result, or the run fails.

## The card's numbers come from JCC-mitigated builds

On a CPU with the Intel JCC-erratum microcode fix (Skylake to Coffee Lake;
this repository's measuring machine is a Kaby Lake), a jump that crosses or
ends on a 32-byte boundary runs from the legacy decoder. Which loops hit
that is layout luck: the same source measured stable `rec` 1k at 0.98× Rust
in one build and 1.25× in the next (`idq.mite_uops` 45 % vs 18 % of uops).
So the card is measured with every side built without such jumps:

```sh
OPT=$(ls .zig-cache/o/*/options.zig | head -1)   # any zl_options of a `zig build` here
zig build-exe -OReleaseFast -fllvm --dep sort --dep testkit -Mroot=modules/sort/tools/bench.zig \
  -OReleaseFast -Msort=modules/sort/src/root.zig \
  -OReleaseFast --dep zl_options -Mtestkit=modules/testkit/src/root.zig -Mzl_options=$OPT \
  --cache-dir .zig-cache -fno-emit-bin -femit-asm=.zig-cache/jcc/bench.s --name bench-sort-jcc
zig build-exe -OReleaseFast -cflags -mbranches-within-32B-boundaries -- .zig-cache/jcc/bench.s \
  --cache-dir .zig-cache -femit-bin=.zig-cache/jcc/bench-sort-jcc
BENCH_JCC_SAFE=1 BENCH_ROUNDS=5 .zig-cache/jcc/bench-sort-jcc
```

Two stages because Zig has no `-mllvm` passthrough: the assembler pads the
branches. `BENCH_JCC_SAFE=1` builds Rust with
`-C llvm-args=-x86-branches-within-32B-boundaries` and C++ with
`-Wa,-mbranches-within-32B-boundaries`. On AMD or Ice Lake and newer the
plain `zig build bench-sort` measures the same thing.

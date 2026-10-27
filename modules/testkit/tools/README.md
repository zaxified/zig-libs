# `testkit` verification instruments

Two instruments, run by hand. `hexprobe.zig` needs no foreign toolchain by
itself (it drives `testkit.hex` through Zig alone), but the comparison it
feeds into needs a **foreign toolchain** (Python). `zig build test-testkit`
must require none of it (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for
data the tests pin, and oracles that drive a foreign implementation through
the public API or wire format. The audit's other probes (golden-diff mutation
harness, base examples, a bare-`return` scanner) were deleted on 2026-09-17;
what they found is pinned by tests in `src/` or filed as open findings.

Figures below were measured on 2026-09-17 against the tree as it stands.

## Two from-scratch decoders agree with `testkit.hex`

| tool | question it answers |
|---|---|
| `hexprobe.zig` | Exhaustively drives every 0..3-byte string over a hostile alphabet through `testkit.hex.into`/`.alloc` — the module's public API only — and prints one TSV line per input. |
| `oracle.py` | Grades that TSV against (a) a strict RFC 4648 decoder written here from scratch, and (b) Python's own `bytes.fromhex`. |

```bash
zig build-exe -OReleaseFast --dep testkit \
    -Mroot=modules/testkit/tools/hexprobe.zig \
    -Mtestkit=modules/testkit/src/root.zig \
    -femit-bin=<scratch>/hexprobe --cache-dir <scratch>/cache
<scratch>/hexprobe > /dev/null 2> <scratch>/hex-zig.tsv   # stderr, not stdout
python3 modules/testkit/tools/oracle.py <scratch>/hex-zig.tsv
```

**Measured 2026-09-17: 16 276 inputs, strict-diffs=0, py-diffs=255.**
`testkit.hex` matches the strict RFC 4648 reference exactly (0 diffs). All
255 disagreements with `bytes.fromhex` are Python's own leniency toward
whitespace inside a hex string (`" 00"`, `"\t90"`, `"\n\n"` all decode under
`bytes.fromhex`) — this module is correctly the stricter of the two, exactly
what `FINDINGS` recorded when it named this class-C anchor.

Needs: Python 3, stdlib only (no third-party package, so no licence to
check).

## The bench's foreign sides

`bench.zig` (kind 3, `zig build bench-testkit -Djcc-safe`) builds and runs
two foreign programs over the same hex property; the method and the figures
are in the module README § Performance.

| dir | what | built by `bench.zig` as |
|---|---|---|
| `proptest_rust/` | the reference: proptest 1.11.0's `TestRunner`, 10 000 cases per op | `cargo build --release --locked --offline` into `.zig-cache/proptest_rust[-jcc]` |
| `libfuzzer_c/` | the fastest candidate: libFuzzer in-process via `LLVMFuzzerRunDriver`, timed from its callback | `clang -fsanitize=fuzzer-no-link` + `libclang_rt.fuzzer_no_main` into `.zig-cache/bench-testkit/foreign_bench` |

`proptest_rust/Cargo.lock` pins the crates. On Linux 14 are built, each
offering MIT (zerocopy: BSD-2-Clause OR Apache-2.0 OR MIT; the rest MIT OR
Apache-2.0). They were read before the first build
(2026-10-27): no proc macro; four build scripts (getrandom, libc,
num-traits via autocfg, zerocopy) that only run `rustc --version`/`-vV`,
compile autocfg's probes into `OUT_DIR` and read the crate's own
`Cargo.toml`. proptest's file writes (failure persistence, `fork`) are off:
`failure_persistence: None`, `default-features = false`.

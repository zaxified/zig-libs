# Zig pitfalls in this repository

General Zig 0.16 API changes and gotchas live in the `zig` skill (`.claude/skills/zig`,
vendored from an audited zaxified/zig-skills release — never edit it here). This file holds
only what is specific to zig-libs.

## Build modes and backends here

Every compile step in every `build.zig` of this repository uses LLVM unless `-Dselfhosted`
is passed. The self-hosted backend is for the edit loop only; no gate and no CI lane uses
it. Each defect class is caught once, in the cheapest place — nothing runs twice in the
same mode:

| when | what to run |
|---|---|
| editing | whatever is fastest; `-Dselfhosted` is fine here |
| before ending work on a module | `scripts/modtest <m>` for **each module you touched** — Debug with LLVM; `heavy` modules build at ReleaseSafe on their own. Nothing else locally. |
| the dependency closure | CI's push lane (`changed modules`), on the push |
| optimized modes, the shipped mode | CI's `ReleaseSafe` and `ReleaseFast` full lanes on a tag or `workflow_dispatch` — "full gate green" is claimed only from CI |
| valgrind, ctgrind, fuzz driver, mutants, benchmarks | `ReleaseSafe` / `ReleaseFast` (`scripts/modtest <m> -Doptimize=ReleaseSafe`) |

- Do not run `scripts/test.sh changed`, `all` or `modules`, or a whole-collection
  `zig build test` locally: the closure and the full matrix are CI's. A PreToolUse hook
  turns the latter into an approval prompt.
- A failure in a module you did not touch: `scripts/modtest <m>` alone; if it passes alone,
  it is load-flaky. Never rerun a full gate to diagnose.
- Example apps build against the pinned release tag in their `build.zig.zon`; to test them
  against this tree: `zig build test --build-file example-apps/<app>/build.zig
  --fork=<absolute path of this repo>`.

## Runtime-dispatched inline asm

A hardware path chosen by CPUID at run time (crc32 `pclmulqdq`, crc32c SSE4.2 `crc32`,
aesgcm AES-NI) is compiled only where the backend can emit it: `pclmul_emittable`,
`sse42_emittable`, aesgcm's `x86_asm`. Under the self-hosted backend that means "the target
CPU model has the feature"; elsewhere the portable path is used. Every gate on such a path —
the dispatcher, `available()`, tests — checks the comptime condition before the run-time
one (`if (!x86_asm or !available(.aesni)) return error.SkipZigTest;`): a run-time skip alone
still compiles the asm.

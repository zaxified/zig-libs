# testkit — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-25** — **CONSUMER-VISIBLE (additive):** `testkit.child` is public: run a function in a forked child and get how it ended (exit code, signal, hang at the limit) -- how a test asserts a panic. First user: workerpool's "wait() from a job panics" test.

- **2026-10-25** — **Added:** `bench.GoBuild.out` (default `"go_bench"`, the old fixed name): the binary's name in the work directory, so a bench can build a second Go program beside its reference (first user: `bench-aaa-gate`'s fast contenders).

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-21** — **Added:** `stackprobe.Expect.residue` (default `true`): `false` checks only
  the needles, for a call whose frames below its burns may hold public data by design (a TLS
  server's unburned client-certificate verification). Self-tested both ways: public residue
  passes, a secret parked after the burn still fails.

- **2026-10-21** — **Fix:** `bench.drive` closes its user-mode cycle counter (`Cycles.close`, new). A bench that calls `drive` once per workload left one counter open per call on the same thread; past the PMU's counters they were multiplexed and each read only part of the cycles, so later workloads' ratios came out too low (tlsserver's bench: workloads 4–6 at 0.35–0.54× by cycles while wall time said 0.46–0.90×). Benches calling `drive` once were not affected.

- **2026-10-20** — **Added:** `bench.Work.fast_only` — a row whose `ref` side is the fastest candidate because the card's reference has no such workload (aescbc's CTS rows); it counts for `Summary.worst_fast`, never for the reference ratio. Since the 2026-10-17 move to `testkit.bench` such rows had gone into the reference ratio (aescbc read ref 1.21× Go from OpenSSL-only rows).

- **2026-10-20** — **Changed (performance):** `fuzz.driver` renews its `SafeAllocator` per batch of seeds (1024, or 64 MiB allocated) instead of per seed; a counting `SeedLedger` still fails a leak on the seed that made it (`error.MemoryLeakDetected`, `FAIL … seed=N: memory leak`). Per-seed init + deinit was ~1 µs (`threads: [128]Thread`), 4.2× a 0.3 µs harness; now 1.03–1.07× a bare loop (`bench-testkit`, whose bare side now also allocates through a `SafeAllocator`). Tests: a leak past a batch boundary, realloc growth/shrink across batches.

- **2026-10-19** — **Fix (test only):** pin the per-seed leak check of `runSeedsReporting` (a harness leaking in one seed returns `error.MemoryLeakDetected`; self-test, silent via `deinitLog(report)`). The leak log is no longer printed when `report` is false (S7 audit).

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README: `std.testing` survey names re-verified against 0.17.0.

- **2026-10-18** — Ported to Zig 0.17.0. `std.meta.Int` -> `@Int`; `wait4` status is `i32`. `runSeedsReporting` (and the shrinker's seed search) give every seed its own `std.heap.SafeAllocator` over the caller's allocator, deinit at seed end: a leak fails that seed (`FAIL <name> seed=N: memory leak`, `error.MemoryLeakDetected`) and the 0.17 never-reusing `testing.allocator` no longer grows with the seed count.
- **2026-10-17** — `stackprobe.Expect.quiet`: a probe expected to fail prints no report (the two positive controls used to write to stderr from a passing test, which a lane treats as a failure).

- **2026-10-17** — `global-alloc-ok` marker on the watchdog test's forked child (`check-global-alloc`). Test only.

- **2026-10-17** — **Added** (S2 wave): `bench` — the comparison driver of `tools/bench.zig` (`timeIt`, `foreign`/`foreignArgv`/`parseForeign`, `Work(Op)`, `score`, `Summary`, `drive`, `goBuild`, `buildForeign`, `foreignOnce`); the 38 benches that carried it by hand now import it (the same tables; two failure messages now say "foreign side" and "the C compiler"). `guard.Guarded(cap).tail/head` — buffers bounded by PROT_NONE pages (brotli's, generalised). **Shrinking:** `fuzz.Rng` gained an optional `tape` (record/replay of every choice; `Rng{ .r = … }` call sites unchanged), `<PREFIX>_SHRINK=<seed>` shrinks a failing seed in forked children to a small tape that fails the same way (error, signal, leak or hang), `_SHRINK_OUT`, `_SHRINK_MS`, `_CHOICES=<path>` traced replay; FAIL/HANG lines now print the shrink command on the next line. **Faults:** `fuzz.FaultPlan`, `ChunkedReader`, `ChunkedWriter`, `failingAllocator`, all drawn from the harness's source. **Fixed:** the seed file cost ~9 µs per seed (`ftruncate`+`pwrite`; a 0.3 µs harness ran 30× slower) — now a shared mapping with digits incremented in place, and the seed file is opened RDWR; the watchdog reads no clock per input (generation counter, hang reported within one 50 ms sampling period after the limit). `fuzz.driver.runSeedsReporting` and `resetReach` are public; the driver resets reach counts at the start of a run. Driver cost now 1.00–1.04× a bare seed loop (`zig build bench-testkit`, new). Own fuzz harnesses (`TESTKIT_FUZZ`: hex, golden, fault, tape).

- **2026-10-17** — Mutation run (schemata, 26 mutants over `fuzz_driver`, `golden`, `hex`, `stackprobe`): 25 killed, 1 equivalent (`hex.into` decoding into the whole buffer — `hexToBytes` returns the prefix anyway). The 6 survivors became tests: the driver's seed loop and failure return (`runSeeds`, now separable from the environment: `parseSpec`, `selected`), `Rng` drawing both ends of a range and its short-length bias, `hit` counting, stackprobe residue under a too-short burn, `analyse` not counting paint as residue. **NO CONSUMER-VISIBLE CHANGE** to `run`'s behaviour; `parseSpec`, `Spec`, `selected` are new public helpers.

- **2026-10-10** — **Added:** `fuzz.ScriptSource` — the driver `Rng`'s method set (plus `boolWeighted`) over
  one `smith.slice` script, so a harness generic over its source runs from a reviewable script under
  `testing.fuzz` instead of collapsing every ranged Smith draw to its minimum (`check-fuzz-reach`).
- **2026-10-09** — **New `stackprobe`: the shared dead-stack probe engine.** `Probe(.{}).run(label,
  f, args, secrets, .{})` runs `f(args)` in a painted stack region and fails on (a) RESIDUE: a byte
  that is neither paint nor zero deeper than the top of the longest zero run (the burn), and (b) a
  NEEDLE: any 16-byte window of the secret inputs and `out` buffers passed in `secrets`, read after
  the call. No per-algorithm needles. Three controls re-measured in every `run` (negative, positive,
  short-burn). `skipUnlessOptimized` skips at RUNTIME, so probe bodies are type-checked in Debug.
  Additive.

- **2026-10-04** — `fuzz.driver.run` skips off 64-bit Linux (`fuzz.driver.supported`) instead of
  failing to compile: its watchdog state is 64-bit atomics (none on mips32) and it calls the
  Linux kernel directly (no `Environ.getPosix` on Windows). The Linux code is not compiled there,
  so brotli, which uses the driver, now builds for mips32 and Windows.

- **2026-10-01** — **New `loopbackSkip`, `loopbackGuaranteed`, `netns_env`.** The give-up for a test
  that cannot get a loopback socket: `error.SkipZigTest` as before, unless `ZIGLIBS_NETNS` is set
  (by `scripts/lib/netns-run`, which brings `lo` up and checks it), where it is
  `error.LoopbackUnavailable` — a test failure. About 25 modules spelled the skip by hand, and a
  skip reports PASS with a summary line that looks identical. Additive.
- **2026-09-28** — **New `fuzz.driver`: the deterministic fuzz driver.** `fuzz.driver.run(harness,
  .{ .prefix, .name })` runs a harness generic over its source of choices over seeded inputs in the
  ordinary test binary — a watchdog per input (`HANG <name> seed=N`, exit 124), `FAIL <name>
  seed=N`, the current seed in a seed file, a progress line a second, replay of a saved `--fuzz`
  input, a leak-finding allocator without stack traces — and `fuzz.driver.hit(label)` counts reach,
  printed as `REACH`. `fuzz.Rng` is `Smith`'s drawing methods from a PRNG. The third copy of the
  driver seglog and zstd carry by hand; first consumer qap. Additive.

- **2026-09-07** — **`fuzz.Cursor`: how a *structured* harness reads a corpus
  seed.** `seed`/`seedHex`/`seedInto` serve a harness that decodes a frame;
  `check-fuzz-reach`'s R1 class is the other kind — state machines and
  generators, where every choice comes from `smith.valueRangeAtMost` and there
  is no byte string to be faithful to. Outside `--fuzz` those collapse
  completely: a scalar draw returns the range MINIMUM unless its whole
  eight-octet word falls inside the range, and after the first short read
  `Smith` discards the rest of the input, so every later draw is the minimum
  too. Measured on `iec61850/control.fuzzPoint`: the one input it ever ran gave
  `ctl_model = status_only`, both timeouts 0 and branch 0 for all 32 rounds —
  0 accepted outcomes, 32 identical refusals. `Cursor` reads those choices out
  of one `smith.slice` instead, which satisfies the gate honestly and makes a
  seed a reviewable script. A short script cycles rather than running out, and
  the **empty** script reads as all zeroes, which reproduces the collapsed
  harness exactly — so a corpus guard can pin the "before" number instead of
  claiming it.

- **2026-09-07** — **`fuzz.seed` / `fuzz.seedHex` / `fuzz.seedInto`.** A
  `std.testing.fuzz` corpus entry is not the frame you want the harness to see:
  `Smith.slice` reads a little-endian `u32` length first, so a raw frame arrives
  minus its own first four octets (measured on `netaddr`: `"192.168.1.1"` reached
  the parser as `"168.1.1"`). Every module that burned its fuzz targets down
  rediscovered that and wrote the same helper — **33 copies across 12 modules in
  three shapes**, growing by roughly eight per module burned down, each carrying
  a comment about the same trap: the returned array has to be container-level or
  the slice dangles with the RIGHT length and garbage behind it.
  The tests are the part that matters. They drive the real `std.testing.Smith`
  over the produced seed rather than round-tripping this file against itself, so
  a future Zig that changes `slice`'s framing fails here loudly instead of
  leaving a dozen modules quietly seeding nothing. Two of them pin hazards that
  cost the burn-down real time: a seed longer than the harness's buffer is not a
  large seed but the EMPTY one (`slice` falls back to the range minimum), and a
  seed is worthless in a harness that opens `bytes` then a ranged length — that
  idiom reads the seed into the buffer (`buf[0] == 'G'`) and then discards it
  with `len == 0`.

- **2026-09-04** — **Second audit pass** (the first was 2026-08-06).
  `expectBytes` had become a printf: deleting
  its `return error.TestExpectedEqual` left the suite at 22/22 green while five
  of five unequal pairs passed, because the wiring from `diff` to the returned
  error was held by nothing. Both of `expectHex`'s refusals were unheld too, and
  swallowing the decode error made `expectHex("zz", &.{})` **pass** — a
  malformed golden compared as though it were an empty one. The cause of all
  three was structural: the decision and its diagnostics lived in one function,
  and a self-test of the failing direction would have written to stderr, which
  `scripts/lib/test-lib.sh` fails even for a passing step. The decision is now a
  silent `verdict`/`hexVerdict` that the failing direction can and does assert;
  `expectBytes`/`expectHex` are those plus `report`. `hex.bytes` no longer
  refuses a valid literal outside a comptime context — the
  `catch @compileError` branch was analysed on every runtime call, so
  `hex.bytes(4, "deadbeef")` in a test body failed to compile accusing its own
  correct argument. New gate `scripts/checks/check-skip-as-pass.py`: `zig test` counts
  a bare `return;` as a PASS, and 11 sites across nftables, ebpf and bacnet
  still announced a skip and then returned plainly — the exact pattern
  `testkit.skip`'s doc comment says it was written to replace.

- **2026-08-18** — Added `getEnv`, a portable env read for test gates: it returns `null`
  on Windows rather than calling `std.process.Environ.getPosix`, whose own body does not
  compile there (`Environ.Block` resolves to `GlobalBlock`, which has no `.view()`).
  `verboseSkip` now goes through it. The unguarded `getPosix` call was the single reason
  21 modules claiming `platform = .any` failed to cross-compile their test binaries for
  `x86_64-windows-gnu`.
- **2026-08-06** — Security audit: no findings. Modeled on `std.testing`, extended
  (design reference, not a test anchor).
- **2026-07-31** — New module: Test-only shared harness (`hex` decoding for KAT vectors,
  golden byte-comparison that names the first differing offset, the verbose-skip
  convention).

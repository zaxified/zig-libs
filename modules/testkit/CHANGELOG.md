# testkit — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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

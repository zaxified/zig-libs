# bfv — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — The production entry points can now actually be compiled by a
  consumer. **BEHAVIOURAL, not BREAKING.** Since the 2026-08-12 entry below,
  `keyGen`, `encrypt` and `genRelinKey` each had a body that called its
  `…ForTest` twin, and each twin opens with
  `comptime if (!builtin.is_test) @compileError("this is a TEST-ONLY entry
  point…")`. Zig analyses a callee through its caller, so the guard fired
  *through* the wrapper: a non-test consumer calling `keyGen(io)` — the very
  entry point the guard's message directs it to — failed to compile. The whole
  production API for keygen, encryption and relin-key generation was
  uncallable outside a test build.

  Fixed by moving each body into a private `…Inner(random: std.Random)`. The
  `std.Io` wrapper calls `…Inner` directly, and the public `…ForTest` twin is
  the guard plus a call to the same `…Inner`. The guard therefore no longer
  sits on the production path, while still refusing any non-test caller of the
  public twin.

  **BEHAVIOURAL** because a public entry point goes from uncompilable to
  compilable, which is a real change in what this module does for a consumer.
  **Not BREAKING**: no signature changes, nothing that compiled before stops
  compiling, and no previously-working call changes its result — `…ForTest`
  now delegates to `…Inner` with the draws in the same order, so the scripted
  word-sequence KAT and every seeded end-to-end vector are bit-identical.

  Why nothing caught it: `builtin.is_test` is true for the whole of
  `zig build test-bfv`, so the deny branch never compiled in CI, and
  `check-testonly` exits 0 either way — it skips modules with no `test_deps`
  (this is one), and its `refAll` walk does not instantiate generics, so
  nothing inside `Bfv(P)` is analysed by it at all (both measured).
- **2026-08-12** — The entropy seam is now typed instead of documented. **BREAKING:** the three
  production entry points that consume entropy — `keyGen`, `encrypt` and
  `genRelinKey` — take `io: std.Io` in place of `random: std.Random` and draw
  through `entropy.SecureSource`, the fail-closed adapter over
  `std.Io.randomSecure`. The old signatures
  survive as `keyGenForTest` / `encryptForTest` / `genRelinKeyForTest` for the
  KATs (including the scripted-word test that pins which draws `keyGen` makes,
  in order) and the seeded end-to-end tests. A caller that was passing a real
  CSPRNG adapts by passing its `std.Io`; a caller that was passing
  `DefaultPrng` no longer compiles, which is the point.

  Why the parameter type and not a doc sentence: `std.Random` is a vtable, so
  `DefaultPrng.init(0).random()` is indistinguishable from a CSPRNG at the call
  site. With `u,e0,e1` predictable an attacker computes `c0 − p0·u − e0 = Δ·m`
  and recovers the plaintext **without the secret key** — encryption randomness
  is the whole of BFV's IND-CPA claim — while `genRelinKey` publishes an
  encryption of `s²` to the evaluator under masks the evaluator can reproduce.
  A `std.Io` cannot be handed a `DefaultPrng`, which is what this change bought.
  It does **not** make a degraded source inexpressible — `std.Io.failing`
  (`std/Io.zig:2509`) is a std-provided `Io` whose `random` returns zeros, and
  `Io.Threaded` itself falls back to a pid+clock+ASLR seed when `getrandom(2)`
  fails. That is why the draws now go through `entropy.SecureSource` rather
  than `std.Io.random`; see `CONVENTIONS.md` §2.2. Two tests pin the shape: one reads the signatures at
  comptime, one shows the `std.Io` path actually draws (two keypairs, and two
  encryptions of the same plaintext, differ) and round-trips.
- **2026-08-11** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: NTT +
  RNS/CRT are byte-exact vs an independent Python re-derivation (`kat_vectors.zig` /
  `kat_test.zig:60-77`).

# tfhe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — The production entry points can now actually be compiled by a
  consumer. **BEHAVIOURAL, not BREAKING.** Since the 2026-08-12 entry below, all
  nine `io: std.Io` entry points — `lweKeyGen`, `glweKeyGen`, `lweEncrypt`,
  `glweEncrypt`, `glweEncryptZero`, `ggswEncryptPoly`, `ggswEncryptScalar`,
  `bootstrapKeyGen`, `keySwitchKeyGen` — had a body that called its `…ForTest`
  twin, and each twin opens with `comptime if (!builtin.is_test)
  @compileError("this is a TEST-ONLY entry point…")`. Zig analyses a callee
  through its caller, so the guard fired *through* the wrapper: a non-test
  consumer calling `lweKeyGen(dim, io)` — the very entry point the guard's
  message directs it to — failed to compile. The module's entire production
  keygen/encryption API was uncallable outside a test build.

  Fixed by moving each body into a private `…Inner(…, random: std.Random)`.
  The `std.Io` wrapper calls `…Inner` directly, and the public `…ForTest` twin
  is the guard plus a call to the same `…Inner`. Because several of these
  compose (`ggswEncryptScalar` → `ggswEncryptPoly` → `glweEncryptZero` →
  `glweEncrypt`, with `bootstrapKeyGen` and `keySwitchKeyGen` on top), the
  rule extends one level down: an `…Inner` calls `…Inner`, never a `…ForTest`
  — otherwise the guard re-enters the production path and nothing is fixed.

  **BEHAVIOURAL** because a public entry point goes from uncompilable to
  compilable, which is a real change in what this module does for a consumer.
  **Not BREAKING**: no signature changes, nothing that compiled before stops
  compiling, and no previously-working call changes its result — the `…ForTest`
  twins delegate with the draws in the same order, so the draw→value KATs and
  the fixed-byte-count assertions are bit-identical.

  Why nothing caught it: `builtin.is_test` is true for the whole of
  `zig build test-tfhe`, so the deny branch never compiled in CI, and
  `check-testonly` exits 0 either way — it skips modules with no `test_deps`
  (this is one), and its `refAll` walk does not instantiate generics, so
  nothing inside `Tfhe(P)` is analysed by it at all (both measured).
- **2026-08-12** — The entropy seam is now typed instead of documented. **BREAKING:** every
  production key-generation and encryption entry point — `lweKeyGen`,
  `glweKeyGen`, `lweEncrypt`, `glweEncrypt`, `glweEncryptZero`,
  `ggswEncryptPoly`, `ggswEncryptScalar`, `bootstrapKeyGen`,
  `keySwitchKeyGen` — takes `io: std.Io` in place of `random: std.Random`
  and draws through `entropy.SecureSource`, the fail-closed adapter over
  `std.Io.randomSecure`. The old
  signatures survive under `…ForTest` names for the draw→value KATs and the
  seeded end-to-end tests; a caller that was passing a real CSPRNG adapts by
  passing its `std.Io`, and a caller that was passing `DefaultPrng` no longer
  compiles, which is the point.

  Why the parameter type and not a doc sentence: `std.Random` is a vtable, so
  `DefaultPrng.init(0).random()` is indistinguishable from a CSPRNG at the call
  site, and a predictable stream does not weaken this scheme — it removes it.
  With `a` and `e` known, `b = ⟨a,s⟩ + μ + e` is a linear equation in `s` and
  `dim` ciphertexts recover the secret key by Gaussian elimination; the
  bootstrap and key-switch keys, which a deployment *publishes* to the
  evaluator, are GGSW/GLWE encryptions of that same key. A `std.Io` cannot be
  handed a `DefaultPrng`, which is what this change bought — but it does **not**
  make a degraded source inexpressible — `std.Io.failing` (`std/Io.zig:2509`)
  is a std-provided `Io` whose `random` returns zeros. That is why the draws now
  go through `entropy.SecureSource`; see `CONVENTIONS.md` §2.2.
  Two tests pin the shape: one reads the signatures at comptime, one shows the
  `std.Io` path actually draws (two keys from one `io` differ) and round-trips.
- **2026-07-18** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on TFHE-rs
  (Rust) / OpenFHE binfhe (C++) (design reference, not a test anchor).

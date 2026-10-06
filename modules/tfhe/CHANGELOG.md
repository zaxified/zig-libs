# tfhe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-05** — **NO CONSUMER-VISIBLE CHANGE:** scope re-survey (`SURVEY-PLAYBOOK.md`); `SPEC.md` only. Scope **mvp → core**, judged against tfhe-rs 1.8.1's `boolean` API and TFHE-lib — the gate-level libraries this module claims to be — not against tfhe-rs's `integer` layer, which is filed as a scope extension. The 2026-10-02 work (real parameter sets, gates, codec, two-way interop) covers the `boolean` user flow its docs describe end to end; the remaining gaps — ~20× slower per gate, no public-key encryption, no bincode/versioned serialisation, no compressed keys, no `KS_PBS` order — are ranked under Backlog. `## Compared with` re-verified (stars, releases, LICENSE files) and given an ahead/even/behind paragraph; two rows added: Lattigo (blind-rotation primitives) and **thedonutfactory/zig-tfhe** (MIT, Zig, needs a C compiler), which the 2026-09-30 survey missed when it said no Zig TFHE existed.

- **2026-10-02** — **BREAKING.** Real parameter sets, binary gates, byte encodings, and tfhe-rs 1.8.1 interop in both directions (maturity task A13; grade 4 → 3, oracle SELF → EXTERNAL).
  - `Params` gains `k` (GLWE dimension, any `k ≥ 1`) and separate `lwe_noise`/`glwe_noise` (`Noise = .uniform | .gaussian`); `err_bound` is gone. New sets `tfhers_default`, `tfhers_tfhe_lib`, `tfhers_2m165` (tfhe-rs's boolean `DEFAULT_PARAMETERS`, `TFHE_LIB_PARAMETERS`, `PARAMETERS_ERROR_PROB_2_POW_MINUS_165`, pinned against tfhe-rs's constants). `toy` keeps its values.
  - Types: `GlweKey.s` is `[k]Poly`; `Glwe` is `{ mask: [k]Poly, body: Poly }`; `LweBig` has dimension `k·N`. GGSW rows and key-switch rows are in tfhe-rs's order (least significant level first; `ggswRowIndex`, `KeySwitchKey.row`).
  - `BootstrapKey`/`KeySwitchKey` live on the heap: `bootstrapKeyGen`/`keySwitchKeyGen` (and their `…ForTest` twins) take an `allocator` first and return `!Key`; `deinit(allocator)` wipes and frees. New `PreparedBootstrapKey` (NTT domain, exact; bit-identical to the reference path) with `bootstrap`/`bootstrapBig`.
  - New `boolean.zig`: `ClientKey`, `ServerKey`, `and`/`nand`/`or`/`nor`/`xor`/`xnor`/`not`/`mux` on tfhe-rs's `±q/8` encoding. New LWE helpers `lweAdd`/`lweSub`/`lweNeg`/`lweScalarMul`/`lweAddConstant`/`lweTrivial`.
  - New `codec.zig` (`Tfhe(P).Codec`): ciphertexts, client/server/bootstrap/key-switch keys; 24-byte header with a parameter fingerprint, payload in tfhe-rs's container order; a server key is read straight into the NTT domain.
  - New `noise.zig`: constant-time Gaussian sampling (branch-free Box–Muller).
  - **BEHAVIOURAL:** `gadget.decompose` now uses tfhe-rs's tie rule (digits in `[−B/2, B/2]`, derived from 40 000 black-box samples), which makes `keySwitch` byte-identical to tfhe-rs's.
  - **Constant time:** `ntt.zig`'s masked selects compiled to `jb` on secret key products (the 2026-09-09 ctgrind finding) — fixed with an inline-asm barrier; the new Gaussian sampler had the same problem (`jbe`), fixed the same way. ctgrind in-file contexts: decrypt 10 → 0, bootstrap 186 → 0, new `noise` target 0. Cost: NTT ~25 % slower.
  - Key generation reads entropy a polynomial at a time (one `getrandom` per call through `entropy.SecureSource`): `tfhers_default` keygen 20 s → 2.2 s.
  - Interop: `tools/tfhers` (tfhe-rs as a black box) writes `src/testdata/tfhers_vectors.bin`; `interop_test.zig` asserts key switching and the bootstrap byte-identical to tfhe-rs, gates across implementations at a `k = 2` set and at `DEFAULT_PARAMETERS`; `tools/tfhers check` ran tfhe-rs's gates on this module's keys (`tools/tfhers/zig_checked.txt`).

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **keygen 0 / encrypt 0 / decrypt 10 / bootstrap 186**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. ⛔ A class-1 finding where the source says there is none, and a clean result where SPEC warned there would be one — in that order. `ntt.zig`'s `addMod`/`reduce128` (`:93`, `:127`) are written as masked selects precisely to avoid a branch, with a comment saying "nothing in this file touches a secret" — a premise that breaks once `Poly.mul` runs on key material. They compile to a real `jb` at 8 inlined sites, while the identical source a few hundred bytes away in `inverse()` compiles to `cmovb`. ⭐ Conversely `gadget.decompose`'s plain `if (d >= half)`, which `SPEC.md` explicitly flags as branching on digit values, **never appears** — LLVM if-converted it; the agent proved the taint genuinely reaches it with `checkMemIsDefined` before reporting the absence, rather than assuming the negative. No secret-indexed memory access exists in the blind rotate: the only index is the mod-switched ciphertext coefficient, which is public. ⚠ `scripts/checks/ctgrind.sh` needed `--max-stackframe=16777216` before any of these numbers meant anything — `std.Io.Threaded` exceeds memcheck's 2 MB default and it then floods with ~7000 bogus "Invalid read/write" errors.

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

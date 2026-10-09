# ed448 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — **Additive API:** pointer twins beside the std-shaped by-value surface: `KeyPair.createInto(out, seed)`, `KeyPair.generateInto(out, io)` (burned; `create` / `generate` now call them and keep their signatures), `SecretKey.fromBytesInto` / `toBytesInto` (plain codecs, no burn). No signature changed. Probe: `src/stackprobe2_test.zig`.
- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, HIGH):** the new ReleaseFast stack
  probe (`src/stackprobe_test.zig`) found the seed, the clamped `s`, `prefix`, the nonce `r` (digest
  and scalar) and `k·s` in dead frames after every `sign`/`signPh` — the bodies' `secureZero` defers
  wipe their own frame only, not the callees' — the seed and `h` after `KeyPair.create`, and the
  clamped scalar after `x448.scalarmult`. `r` beside the signature is the key. `sign`/`signPh`,
  `KeyPair.create`, `Point.mul`, `Point.mulBasePoint` and `x448.scalarmult` now burn their stack
  (`burn.zig`), and secrets cross the API by pointer with secret results in out-params, so no copy
  lands in the caller's frame either: `sign`/`signPh(kp: *const KeyPair, …)`,
  `KeyPair.create(seed: *const [57]u8)`, `x448.scalarmult(out, k: *const, u) !void`,
  `x448.recoverPublicKey(k: *const)`, `x448.KeyPair.generateDeterministic(out, seed: *const) !void`,
  `x448.KeyPair.generate(out, io)`. 0 residues after, caller's frame included.
- **2026-10-07** — **NO CONSUMER-VISIBLE CHANGE:** the `testing.fuzz` harness
  bodies are now generic over their source and run by testkit's deterministic
  driver `ED448_FUZZ` (new `src/fuzz_test.zig`, a seed loop with reach checks in
  every test run); test code only. New `tools/bench.zig` (`zig build bench-ed448`) against OpenSSL Ed448/X448.
- **2026-10-04** — Fix (BEHAVIOURAL): `verify`/`verifyPh` now reject `S >= L` themselves
  (`error.InvalidScalar`). Before, only `Signature.fromBytes` checked it, so a `Signature`
  built field by field with `S + L` (or bits 448..455 set) verified — a malleable second
  encoding (RFC 8032 §5.2.7 step 1). Signatures parsed with `Signature.fromBytes` are
  unaffected. Found by a mutation run (58 mutants, 56 killed, 2 equivalent); tests added
  for `Point.mul` (against the RFC 8032 public keys), the cofactored equation, the
  public-key guard on its own, small-order X448 inputs, a 255-octet context and limb-wide
  `Fe.isZero`/`Fe.eql`.
- **2026-08-13** — Test-only, neither BREAKING nor BEHAVIOURAL: both `x448.zig` and
  `ed448.zig` gained a seam test proving their `KeyPair.generate`'s
  `entropy.fill` draw is actually read (two key pairs from the same `io`
  must differ) and that the production path still round-trips end to end
  (X448: a two-sided DH shared-secret agreement; Ed448: sign/verify).
  Before this, either curve's signing/DH key draw could be replaced by a
  constant and the suite stayed green — confirmed by mutating both draws
  simultaneously (`@memset(&seed, 0x42)`) and watching both new tests fail,
  each on its own file's distinctness assertion (`x448.test...`/
  `ed448.test...`, 54 pass, 2 fail), then reverting to green (56/56). Does
  not distinguish real entropy from a varying-but-weak PRNG; see the tests'
  own comments.
- **2026-08-12** — Both `KeyPair.generate` entry points — `x448.KeyPair.generate` and
  `ed448.KeyPair.generate` — draw their seed through the new `entropy`
  module (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of
  `io.random`. Not breaking: `fill` returns `void`, so both still read
  `generate(io: std.Io) KeyPair` and no caller changed. `std.Io.random` is
  a CSPRNG whose contract permits a silent fallback to a weaker seed
  (`std/Io.zig:2462`) and the default `Io.Threaded` takes it, seeding from
  pid + wall clock + an ASLR pointer. The seed *is* the private key in both
  cases (X448's scalar; Ed448's `s` and nonce `prefix` are both derived
  from it), so a degraded draw is a recoverable DH secret or a forgeable
  signature. `generateDeterministic` / `create` are untouched — a
  caller-supplied seed stays a caller-supplied seed.
- **2026-07-18** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  8032 §7.4's published test vectors.

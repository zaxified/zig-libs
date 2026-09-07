# bn254 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — The three precompile fuzz targets ran exactly one input each, for ever.
  Each drew `smith.bytes(&buf)` and then a ranged length, which returns the range minimum
  when fewer than eight input octets remain, so the length was 0 on every input; with no
  corpus the lane replayed `ecAdd("")`, `ecMul("")`, `ecPairing("")`. ⛔ All three of those
  **succeed** — EIP-196 right-pads short calldata so empty input decodes `p = q = O`, and
  EIP-197's empty product is `true` — so no crash and no "nothing accepted" could ever have
  reported it. ⛔ The `ecPairing` buffer was also 416 octets against this module's own
  1920-octet `ten_point_match_*` vectors, and a seed longer than the buffer reads back
  EMPTY: the largest calldata bn254 owns could not have passed through the harness meant to
  fuzz it. The draw is now one `smith.slice(&buf)`, the `ecPairing` buffer is
  `10 * pair_encoded_bytes + 32`, and each target's corpus is the full official
  go-ethereum vector table plus the refusals that table has none of (a nibble off a real
  point, a coordinate above the field modulus, an off-multiple length). Measured: 18/19,
  22/23 and 16/17 non-empty seeds reach the decoder where 0 did; 16, 21 and 14 accepted,
  of which **10** and **18** results are not the point at infinity and **2** pairing checks
  return `false`. Those second numbers are pinned precisely because the empty input cannot
  produce them, and an accepted count here would have been satisfied by it.

- **2026-09-03** — Drift re-audit. **`bn254` is now on the constant-time
  gate.** `1892c814` replaced `Fp`'s `std.crypto.ff` backend with ~450 lines
  of hand-written constant-time Montgomery arithmetic and the module was not
  on the ctgrind list, so none of it had ever been measured -- the same
  structural gap that let `p256`'s HIGH survive an audit.
  `modules/bn254/src/ctgrind_harness.zig` plus recipes in `scripts/ctgrind.sh`
  and rows in `scripts/ctgrind-expected.tsv` close it, and the first run found
  something: **`Fp.ctSelect`'s mask was not laundered through `blackBox`**,
  although that barrier's own doc comment describes exactly this pattern and
  names its consequence as "a secret-dependent branch on the Groth16 prove
  path" -- and `ctSelect` in the `G1` ladder is where a SECRET bit is selected
  on. Adding it removes one memcheck context (6 -> 5), so it changes real
  codegen. ⚠ **Recorded, not fixed:** three of the five remaining contexts are
  `std.crypto.ff` reached through `Fr.toBytes`, i.e. the conversion that feeds
  the branchless ladder is itself not branchless. Closing that means giving
  `Fr` the hand-written backend `Fp` has. See SPEC "Constant time".
- **2026-09-03** — `Fp.fromInt` no longer has illegal behaviour on a caller's
  choice of `T`. The `std.crypto.ff` path it replaced returned
  `error.Overflow` for a negative value and rejected `@bitSizeOf(T) > 256` at
  compile time; the rewrite's bare `@intCast` dropped both, so
  `fromInt(i32, -1)` was a caught panic in ReleaseSafe and a **SIGSEGV in
  ReleaseFast**, while the declared error set still promised a reported
  rejection. Latent -- no in-repo call site passes a signed or oversize `T`.
- **2026-09-03** — Test teeth for `geP`, the sole enforcement of EIP-197's
  "an encoding value of `p` or larger is invalid" for every coordinate of
  every precompile call. It was pinned at `p` and `p - 1` only, so a
  compiling FALSE-ACCEPT mutation (skipping one limb of the comparison)
  shipped with all 163 tests green -- the 49 official Ethereum vectors
  included, since every one of them is a SUCCESS case and none can express a
  non-canonical coordinate. Now exercised at every limb in both directions,
  with `p_int` rather than `geP` as the oracle.
- **2026-09-03** — Documentation caught up with `1892c814`/`a1d72299`, six
  weeks late. `SPEC.md`, `README.md`, `root.zig`'s `meta.model_after` (the
  catalog's source of truth) and `fp6.zig` all still said `Fp` rides on
  `std.crypto.ff` and is "canonical at rest" / "deliberately left alone";
  the tier assessment rested on it, and the Backlog still listed persistent
  Montgomery storage and precomputed Frobenius tables as future work after
  both had shipped. A contributor following the sentence would have produced
  byte-wrong `toBytes`. Also: `montSqr`'s doc named `montMul(a, a)` as its
  correctness oracle when the differential test uses `std.crypto.ff`'s
  `Modulus.sq` (an EXTERNAL oracle, which is the stronger claim), and
  README's Verify block labelled the default lane "Debug" when `heavy: true`
  forces ReleaseSafe.
- **2026-09-03** — Recorded, not fixed: the three `testing.fuzz` harnesses
  reach their target exactly once, with the empty input, because they carry
  no corpus and `zig build --fuzz` does not complete on this toolchain. Give
  them the hostile shapes (63/64/65/96/128/191/192/193-byte lengths, a
  coordinate of `p`, a non-subgroup `G2`) when the fuzzer is usable again.


- **2026-08-22** — Re-export `EcPairingError` at the module root. `ecPairing` and
  `ecPairingCheck` return it, but only `PrecompileError` — a strict subset, missing
  `error.OutOfMemory` — was aliased there, so a caller naming either function's error
  set from outside got a set that does not compile. Found by the module's first
  outside consumer (`example/main.zig`), not by any test in here.
- **2026-07-18** — Security audit: five findings fixed, four documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on gnark-crypto (Go+asm) /
  arkworks (Rust) / libff (C++); py_ecc = correctness oracle only (design reference, not
  a test anchor).
- **2026-07-15** — New module: BN254 / alt-bn128 curve — Parts 1-6 COMPLETE: field tower
  + G1/G2 + optimal-ate pairing + EIP-196/197 precompiles + Groth16 verifier.

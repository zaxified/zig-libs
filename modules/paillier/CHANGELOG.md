# paillier — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **crt 331 / noncrt 141 / mul 12 / addm 10**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. ⭐ Confirms both leads `threshold_ecdsa` raised indirectly, and CORRECTS one: the L-function's variable-time `divFloor` is real on every run, but at `root.zig:1253`, not the `:1205`/`:1213` that report cited — `:1205` is the PUBLIC ciphertext check and correctly never fires under taint. `mulPlaintext`'s `if (k.isZero())` at `root.zig:1304` is confirmed exactly, is a direct branch on a raw secret exponent, and is **not mentioned anywhere in SPEC.md** — an undocumented gap rather than a contradicted claim. ⭐ SPEC's binomial-shortcut claim ("a possibly-secret plaintext `m` never enters a bit-scanned exponent path") is true of this module's own control flow but NOT end to end: `std.crypto.ff.Modulus.mul`'s Montgomery machinery branches on `m`, **verified by disassembly to be a real `test`/`jne` and not a `cmov`** — the first agent in this campaign to settle that question by instruction rather than argument.

- **2026-09-07** — The three byte-loader fuzz targets had never parsed a field. Every draw
  went through `fuzzedFieldBytes`, which opened with `smith.bytes(buf)` and then took its
  length from a ranged draw — and a ranged draw returns the range minimum once `bytes` has
  eaten the input, so the length was 0 for every field on every input. With no corpus
  either, the lane ran exactly one call per target: `PublicKey.fromBytes("", null)`,
  `SecretKey.fromBytes("", "", "")`, `Ciphertext.fromBytes(pk, "")`. ⛔ Two of the biases
  the helper existed for were dead for a second, independent reason: they hung on
  `smith.value(bool)` drawn *after* the byte draw, so the input was exhausted and the bool
  was false every time. The leading-zero run (`stripLeadingZeros`) never happened once, and
  `g_bytes` was `null` on every single run — `PublicKey.fromBytes`'s explicit-generator
  branch had **never executed**, and no corpus could have fixed that without changing the
  harness. The draw is now one `smith.slice`, an empty second frame means "standard
  generator `g = n+1`" so the seed decides, and both biases live in the corpus where they
  are reproducible: the boundary lengths are seeds sized by the same `boundaryLen` the dead
  knob used, and a leading-zero run is a seed with leading zeros. The positive seeds come
  from a real 512-bit key this module generates, because a `lambda` canonical mod `n²`
  beside a `mu` canonical mod `n` for the same `n` is not a shape any draw produces.
  Measured: 16/17, 10/12 and 7/8 seeds carry a non-empty first field where 0 did; 10, 6 and
  5 accepted, of which **2** went through the explicit-`g` branch, **4** distinct `n`
  bit-widths came back out, and **3** ciphertexts were non-zero. The last number is pinned
  rather than `accepted` because `stripLeadingZeros("")` is `""` and `Fe.fromBytes` reads
  that as zero — the empty input this target ran for ever is *accepted*.

- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Value-exact vs `phe`
  (python-paillier) 1.5.0. Toy key p=11,q=17: n_sq/λ/g/µ and concrete (m,r)→c
  cross-checked (`root.zig:1000,1026`, NOTICE).
- **2026-07-14** — New module: Paillier additively-homomorphic PKE (P. Paillier,
  EUROCRYPT 1999) over `std.crypto.ff`.

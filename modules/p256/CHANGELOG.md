# p256 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — tests: deterministic fuzz driver `P256_FUZZ` over the existing harnesses (`fromSec1` gains a pristine/flipped overlay: genuine encodings of `k*G` must decode to it, a flipped `y` bit must be refused).
- **2026-10-09** — New `KeyPair.signerInto(out, key_pair, noise)`: the `Signer` holds the secret
  key, and `signer` returns it by value, so the key sat in the caller's result slot (18 needle windows,
  `stackprobe2_test.zig`). Additive; `signer` stays (std shape, now documented).
- **2026-10-09** — **Additive API + burn:** `EcdsaP256Sha256.KeyPair.signer` now runs under a burn; new pointer twin `KeyPair.generateInto(out, io)` beside the std-shaped `generate` (which calls it). No signature changed. Probe: `src/stackprobe2_test.zig`.
- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, HIGH):** the new ReleaseFast stack
  probe (`src/stackprobe_test.zig`; the nonce is solved from the returned signature, so std's own
  nonce is covered) found the secret key, the nonce `k`, `k⁻¹`, `r·d` and `e + r·d` in dead frames
  after every signature — `ecdsaSign`, `ecdsaSignDeterministic` and `EcdsaP256Sha256.KeyPair.sign`
  with and without noise — the key after `KeyPair.fromSecretKey`, and the key and the shared
  point's `y` after an ECDH `P256.mul` + `affineCoordinates`. `k` beside the signature is the
  private key. `P256.mul`, `combMulBase` and `affineCoordinates` now burn their stack
  (`burn.zig`; std's `Ecdsa` reaches them through `Curve.basePoint.mul`), `ecdsaSign`/
  `ecdsaSignDeterministic` take the key and nonce by pointer and burn, and `EcdsaP256Sha256` is
  now a wrapper over std's `Ecdsa(P256, Sha256)` rather than an alias: same declarations, its
  own `KeyPair` type (same fields) whose `sign`/`signPrehashed`/`signer` take `*const KeyPair`
  (`kp.sign(...)` reads the same) and burn, as do `Signer.finalize`, `generateDeterministic` and
  `fromSecretKey`. The std-shaped forms (`P256.mul` is std's curve interface, `KeyPair` std's
  surface) still leave by-value copies in the caller's frame; new, additive:
  `P256.mulInto(p, out, s: *const, endian)` for ECDH, `KeyPair.fromSecretKeyInto(out, sk: *const)`
  and `KeyPair.generateDeterministicInto(out, seed: *const)`, which leave none.
- **2026-09-29** — **Performance: the RFC 6979 nonce derivation keys HMAC-SHA-256 once per K.**
  `ecdsaSignDeterministic`'s DRBG called `HmacSha256.create` for every step, re-absorbing the
  key's inner and outer pads each time although K changes only twice per nonce. A private
  `KeyedHmac` keeps the two SHA-256 states after `K ^ ipad` / `K ^ opad` and clones them per
  message (2 compressions for a short message instead of 4). For the usual first-candidate nonce
  that is 22 -> 18 compressions. No API change; the nonce and the signature bytes are identical
  (kept-as-oracle copy of the old function, 3000 random key/hash pairs, plus the RFC 6979 A.2.5
  `k` values for "sample" and "test"). No key-dependent branch or index added: pad derivation and
  absorption are data-independent; the module's existing rejection loop is unchanged.

- **2026-09-28** — **Performance: ECDSA sign 97 → 29 µs, verify 261 → 128 µs
  (std's generic `EcdsaP256Sha256.verify` over this group 413 → 125 µs)**, same
  core, interleaved before/after, ReleaseFast. No API removed or changed; three
  additions. Profile first (`perf`, `--call-graph lbr`): a signature was 46 %
  fixed-base comb, **45 % `Scalar.invert`** (std's fiat divstep, one divstep per
  5-limb call, 741 calls, ~40 µs — the same symbol is 9.7 % of a whole qap TLS
  handshake) and 13 % Fermat `Fe.invert`; a verify was 73 % the projective RCB
  double-base multiply. SPEC's "scalar field NOT on the critical path" was wrong
  by half a signature and is rewritten.
  1. `src/modinv.zig` (new): constant-time Bernstein–Yang safegcd, 590 divsteps
     in ten 62-bit batches (libsecp256k1 `modinv64` shape), generic over the
     modulus. `Fe.invert` 12.5 → 2.3 µs, `Scalar.invert` 31–41 → 2.2 µs. Gated by
     the new `gate.fast_invert_implemented`; the oracles stay (`Fe.invertFermat`,
     `Scalar.invertStd`, both new `pub`) and pin it on random draws + edges (0 → 0,
     1, `m−1`, `m−2`, limb seams) for both moduli, plus `x·x⁻¹ ≡ 1` under a
     bignum `% m`. ⚠ Found during bring-up: the correction factor must be `+m⁻¹
     mod 2^62`, not `−m⁻¹`; with the wrong sign 20 of 44 tests went red (RFC 6979
     and Wycheproof included) — the harness has teeth.
  2. `src/scalar.zig`: `P256.scalar` is now this module's namespace — a wrapper
     over std's scalar with the same surface (`Scalar`, `CompressedScalar`,
     `rejectNonCanonical`, `reduce48`, …; every consumer spelling checked: jwt,
     jwe, xmldsig, webauthn, hpke, spake2plus, ctap2pin, ocsp) — so std's generic
     `Ecdsa(P256, Sha256)` signer reaches the fast inverse. `Scalar` is a new
     type; nothing compared it to std's by identity. A test pins that every
     forwarded operation still matches std byte for byte.
  3. `src/field.zig`: `Fe.add` does one conditional subtract (inputs are
     canonical, so `a + b < 2p`) instead of the two-fold `normalize`: 10.0 → 5.3
     ns; a point operation has ~15 of them (RCB dbl 536 → 468 ns).
  4. `src/group.zig`: `P256.addMixed` (new `pub`, RCB Algorithm 5, complete,
     limb-identical to `add` with `Z2 = 1` — tested so); the fixed-base table is
     now `base_table` / `BaseTable` (was `comb_table` / `CombTable`; both were
     `pub` but had no consumer outside `oracle_test.zig`): 43 windows × 32 affine
     entries (w = 6, 88 064 B `.rodata`, was 49 920 B), batch-normalised at
     comptime with one inversion; CT `k·G` 40 → 25 µs, same `blackBox`-laundered
     masked gather (digit 0 is undone by a masked blend, since `(0, 0)` is not a
     point). Vartime verify paths moved to Jacobian coordinates (`Jac`, private:
     dbl 3M+5S, mixed add 7M+4S, exceptional cases as branches on PUBLIC data
     only); `basePoint.mulPublic` is served from the fixed-base table with no
     doublings (this is what std's generic verifier calls), `Q.mulPublic` is a
     w = 5 wNAF over a batch-normalised affine odd-multiple table, and
     `mulDoubleBasePublic` with `G` in either slot joins the two. Results are the
     same points as before and as std (affine-compared everywhere); their
     projective representation differs. New tests: `basePoint.mulPublic` vs std +
     the comb on random scalars and every recoding edge (`n` → refused, `2^256−k`,
     the top-window boundary); double-base with `G` in either slot, with a
     second representation of `G`, and the join's `P = ±Q` cases. The corrupted-
     table positive control now plants `G` in window 10 (an affine table has no
     identity to plant). Mutants (Jacobian doubling `8β → 4β`, mixed add
     `3·Z1 → 2·Z1`, in a copy under `.zig-cache`): 18 of 47 tests red, including
     each new one.
  Verified: `modtest p256` ReleaseFast + ReleaseSafe 46 pass / 1 skip (was 37);
  `-Dtarget=aarch64-linux -fqemu` 45 pass / 2 skip (portable field, `i128`
  safegcd, comptime table all exercised); dependents ReleaseFast: jwt 118,
  xmldsig 51, jwe 62, webauthn 74, hpke 84, spake2plus 37, ctap2pin 42, ocsp 37;
  `scripts/checks/ctgrind.sh --check p256` OK — `comb` 2 in-file (the
  `rejectIdentity` check, now two jumps), `sign` ≤ 12 (2 × 2 comb + std's five
  canonicality compares + one of the same class in `Scalar.invert`'s
  re-encoding + `isZero` on `r`/`s`), controls and traps 0; the `sign` row's
  output digest is unchanged (byte-identical signatures). `--check hpke` OK.
  Backlog: the word-shuffle reduce bounds `Fe.mul` at ~33 ns (`Fe.sq` gains
  nothing over it); a Montgomery-domain core is the next ~0.7× and is written up
  with its estimate in SPEC backlog 8.

- **2026-09-18** — **NO CONSUMER-VISIBLE CHANGE:** the test that claimed to catch a deleted
  `basePoint.mul` → `combMulBase` redirect did not: with the redirect line removed all 37 tests
  passed, because it asserted only the predicate `isBasePointRepr`, which answers correctly with
  nothing calling it. `combMulBase` now keeps a call counter in test builds only
  (`comb_calls_for_testing`, `void` otherwise, so the ctgrind harness binary is unchanged and only
  the `group.zig` source digests were re-pinned), and the test asserts the comb runs once for
  `basePoint.mul`, not for another point, and at least once under ECDSA signing. Mutant (redirect
  deleted) → RED, `expected 1, found 0`.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added, so this module's `SPEC.md` § "Constant-time contract" has an instrument for the first time. Targets `comb` (a tainted scalar through `combMulBase`) and `sign` (a tainted seed through `generateDeterministic` + `sign`); `mulPublic`/`mulDoubleBasePublic` are deliberately untainted, being documented variable-time on public inputs. Measured ReleaseFast: **1 in-file context for `comb`, 9 for `sign`**, untainted control 0 and no-`-fvalgrind` trap 0 in every row. All ten are negligible-probability degenerate checks — `combMulBaseFastWithTable`'s `rejectIdentity` (`group.zig:512`), five scalar-canonicality checks in std's `common.zig:75`, and `isZero` on the output `r`/`s` — the same class `k256`'s harness already measured and accepted. ⭐ The PATTERN names std's `ecdsa.zig`/`common.zig`/`scalar.zig` on purpose: the shipped ES256 surface is std's generic signer over THIS module's group (`src/sign.zig` is, in its own words, a verification-harness surface), and attributing that arithmetic to someone else is exactly the evasion `scripts/checks/ctgrind.sh` exists to refuse.

- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/kat_vectors.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-09-07** — Fuzz reach: `fuzzFromSec1` never decoded a point. It opened
  `smith.bytes(&buf)`, then chose the SEC1 tag from `smith.valueRangeAtMost(u8, 0, 4)`
  and the length from `smith.valueRangeAtMost(u8, 0, 65)`. A `Smith` ranged draw reads
  eight octets as a little-endian `u64` and returns the range MINIMUM when fewer remain,
  and `bytes` had already consumed the input — so outside `--fuzz` the tag was 0 and the
  length was 0 on **every** run, and the target had no corpus, so the single input it ever
  executed was `fromSec1(&.{})`, refused on the `s.len < 1` line. Measured 2026-09-07:
  1 round, 0 non-empty inputs, 0 points decoded. The draw is now one `smith.slice(&buf)`
  and the target carries 14 real SEC1 encodings — the identity, `G` and `2G` in both
  compressed and uncompressed form, plus one seed per typed refusal (`NotSquare` via
  x = 1, `NonCanonical` via x = p, an off-curve `(x, y)`, tag 5, and three length errors).
  A corpus guard draws exactly as the harness does and pins 13 non-empty, 6 accepted and
  5 on-curve non-identity points, so a future collapse of the draw fails a test rather
  than passing quietly. ⛔ The seed helper is a nine-line COPY of
  `testkit.fuzz.seedHex` rather than an import, and that is deliberate: putting `testkit`
  in p256's `test_deps` enrols the module in `zig build check-testonly`, whose 3-deep
  public-decl walk reaches `P256.scalar` (std's P-256 scalar field) and forces `sqrt`,
  which is `@compileError("unimplemented")` in `std/crypto/pcurves/common.zig:280`
  because the group order is 1 mod 4. Measured 2026-09-07 on an unmodified p256 tree with
  only the `test_deps` line added: `check-testonly` goes from 3 failing probes to 4. The
  copy carries its own `Smith`-driven anchor test so it cannot silently drift from the
  shared helper's framing; delete it when p256 stops re-exporting that scalar field.

- **2026-09-06** — Licensing: added `NOTICE` (kind `third-party attribution`). No code
  changed and no behaviour changed — the module has shipped 725 Apache-2.0 Wycheproof
  ECDSA-P256/SHA-256 vectors (`src/wycheproof_kat_vectors.zig`,
  `src/wycheproof_der_kat_vectors.zig`, 358 315 B, 330 distinct authored comment strings)
  since they were committed, and the condition has been in force that whole time; only
  the record was missing. `NOTICE` reproduces the Apache License 2.0 in full (§4(a)),
  retains the upstream copyright notice (§4(c)), states what
  `scripts/gen/gen-p256-wycheproof.py` changes (§4(b)), and records that upstream ships no
  `NOTICE`, so §4(d) propagates nothing. All 725 rows were re-fetched from upstream and
  compared field by field before the file was written.
- **2026-07-21** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against RFC 6979's published
  test vectors.
- **2026-07-19** — Performance: gained an asm/Montgomery core (part of a collection-wide
  performance campaign that also covered the sibling `k256`/`montint`
  modules; the root changelog records no further detail than this).

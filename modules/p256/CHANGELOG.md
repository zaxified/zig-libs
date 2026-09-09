# p256 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added, so this module's `SPEC.md` § "Constant-time contract" has an instrument for the first time. Targets `comb` (a tainted scalar through `combMulBase`) and `sign` (a tainted seed through `generateDeterministic` + `sign`); `mulPublic`/`mulDoubleBasePublic` are deliberately untainted, being documented variable-time on public inputs. Measured ReleaseFast: **1 in-file context for `comb`, 9 for `sign`**, untainted control 0 and no-`-fvalgrind` trap 0 in every row. All ten are negligible-probability degenerate checks — `combMulBaseFastWithTable`'s `rejectIdentity` (`group.zig:512`), five scalar-canonicality checks in std's `common.zig:75`, and `isZero` on the output `r`/`s` — the same class `k256`'s harness already measured and accepted. ⭐ The PATTERN names std's `ecdsa.zig`/`common.zig`/`scalar.zig` on purpose: the shipped ES256 surface is std's generic signer over THIS module's group (`src/sign.zig` is, in its own words, a verification-harness surface), and attributing that arithmetic to someone else is exactly the evasion `scripts/ctgrind.sh` exists to refuse.

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
  `scripts/gen-p256-wycheproof.py` changes (§4(b)), and records that upstream ships no
  `NOTICE`, so §4(d) propagates nothing. All 725 rows were re-fetched from upstream and
  compared field by field before the file was written.
- **2026-07-21** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against RFC 6979's published
  test vectors.
- **2026-07-19** — Performance: gained an asm/Montgomery core (part of a collection-wide
  performance campaign that also covered the sibling `k256`/`montint`
  modules; the root changelog records no further detail than this).

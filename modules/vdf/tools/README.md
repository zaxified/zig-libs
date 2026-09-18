# `vdf` verification instruments

One instrument, run by hand. Not wired into `zig build`: the value side
needs OpenSSL's `libcrypto`. `zig build test-vdf` requires none of it
(`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners, per-finding probes and timing-only
parts were deleted on 2026-09-17 (finding O1's disposition); a `perf_openssl_oracle.py`
version of this same idea also measured OpenSSL `BN_mod_exp` wall time per squaring for
a delay-calibration finding (F5) — that timing-only part is NOT kept here, only the
value comparison.

## Does OpenSSL agree with `eval`, far beyond the shipped KATs?

| tool | question it answers |
|---|---|
| `eval_driver.zig` | `y = 5^(2^k) mod N` through this module's public `eval` (N = the shipped RSA-2048 Factoring Challenge modulus). |
| `openssl_oracle.py` | The same value via OpenSSL's `BN_mod_exp` (independent modexp implementation), folded into the quotient `Z_N*/{±1}` the same way `eval` does, so the two are byte-comparable. |

```bash
scripts/lib/capped zig build-exe --cache-dir .zig-cache/o1-vdf \
  -femit-bin=.zig-cache/o1-vdf/eval_driver \
  --dep vdf --dep montint \
  -Mroot=modules/vdf/tools/eval_driver.zig \
  --dep montint -Mvdf=modules/vdf/src/root.zig \
  -Mmontint=modules/montint/src/root.zig \
  -OReleaseFast
.zig-cache/o1-vdf/eval_driver 200000 2> zig.txt
python3 modules/vdf/tools/openssl_oracle.py 200000 > openssl.txt
diff zig.txt openssl.txt && echo MATCH
```

**Measured 2026-09-17** (OpenSSL 3.5.5, this machine): `k=1000` and `k=200000`
both **MATCH** byte for byte (512 lowercase hex chars each) — `k=200000` is
20× past the largest KAT `T` shipped in `kat_test.zig` (`10_000`).

Licence: OpenSSL 3.5.5's `libcrypto` is Apache-2.0 (per this system's
`/usr/share/doc/libssl3t64/copyright`, `Files: *` stanza — a few peripheral
files under the same package are `Artistic`/`GPL-1+`, not `BN_mod_exp` or
anything on its call path). Loaded via `ctypes` at runtime from the system
package; nothing from it is vendored into this tree.

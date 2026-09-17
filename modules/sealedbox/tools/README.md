# `sealedbox` verification instruments

Two instruments, run by hand. Neither is wired into `zig build`: they need a
**foreign toolchain** (PyNaCl, i.e. libsodium via CFFI). `zig build
test-sealedbox` must require none of it (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for
data the tests pin, and oracles that drive a foreign implementation through
the public API or wire format. The audit's mutation runners, per-finding
probes, and benchmarks (dead-stack scans, ctgrind probe, forgery replay,
small-order key sweep) were deleted on 2026-09-17; what they found is pinned
by tests in `src/` or filed as open findings (`verify_kat.py`, the other
audit script that once lived beside these, belongs to a separate, rejected
shared KAT-provenance verifier — not adopted here).

Figures below were measured on 2026-09-17 against the tree as it stands.

## A bidirectional differential against real libsodium

| tool | question it answers |
|---|---|
| `driver.zig` | Line protocol over stdin/stdout exposing `sealedbox.seal`/`.open` — the module's real, unmodified public API, nothing internal — so an external process can drive it. |
| `diff_pynacl.py` | Runs N random cases three ways: (1) module seals with a pinned ephemeral key, checked byte-exact against an independent recomputation of libsodium's own `crypto_box_seal.c` construction; (2) module seals with real entropy, libsodium opens it; (3) libsodium seals, the module opens it. Plus a negative control on the BLAKE2b nonce argument order. |

```bash
zig build-exe -OReleaseFast --dep sealedbox \
    -Mroot=modules/sealedbox/tools/driver.zig \
    -Msealedbox=modules/sealedbox/src/root.zig \
    -femit-bin=<scratch>/driver --cache-dir <scratch>/cache
python3 modules/sealedbox/tools/diff_pynacl.py <scratch>/driver 2000
```

**Measured 2026-09-17, N=2000 (6000 comparisons): 6000/6000 agree, 0
mismatches.** Byte-exact vs. the libsodium recomputation: 2000/2000. Libsodium
opens the module's ciphertext: 2000/2000. The module opens libsodium's
ciphertext: 2000/2000. Negative control (swapped nonce argument order)
correctly diverges — the comparison has teeth.

**Licence, checked at the source:** PyNaCl 1.5.0 is Apache License 2.0
(`License: Apache License 2.0` in its installed dist-info `METADATA`). Not
copyleft; fetched/installed only, never vendored into this tree.

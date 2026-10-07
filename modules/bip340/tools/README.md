# `bip340` tools

## `bench.zig` — comparative benchmark against libsecp256k1

The program behind the `**Performance:**` line of the maturity card
(`CONVENTIONS.md` §9, kind 3). Not a test, not run by any lane.

```bash
zig build bench-bip340        # always ReleaseFast; run from the repository root
```

It compiles `c_bench/secp_bench.c` together with libsecp256k1 v0.8.0's own
sources (`secp256k1.c`, `precomputed_ecmult.c`, `precomputed_ecmult_gen.c`) with
`zig cc -O3`, never with the library's build system. The source tree is looked
up in `.zig-cache/foreign/secp256k1/secp256k1-0.8.0` or `$SECP256K1_SRC`; if it
is missing the program prints the fetch recipe (tarball sha256
`eb52b0e9239dff7dc26be5f9623567141b8720ec47da29eb3c1e0a660d17c8bb`) and exits 2.
Review a downloaded tree before compiling it.

Interop is checked before any timing: libsecp256k1's signature must verify here,
ours must verify there, and the two are compared byte for byte. Rows: keypair,
sign, verify (ratios) and `verifyBatch` per signature (ours only, no ratio).

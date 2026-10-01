# `bulletproofs` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test.

| file | produces | needs |
|---|---|---|
| `dalek/emit_zig_proofs.zig` | `dalek/zig_proofs.txt` — 16 range proofs made by this module's `prove` (n = 8/16/32/64), one `<n> <label hex> <V hex> <proof hex>` per line, then 5 aggregated ones from `proveMultiple` (m = 2/4/8) with the commitments joined by `,` in the V field. Random on every run (the prover blinds from getrandom), so the committed file is one run. | Zig |
| `dalek/` (Cargo project) | `src/interop_vectors.zig` — merlin challenges, dalek's Pedersen bases, 14 dalek range proofs and 6 dalek aggregated proofs (ChaCha20-seeded), and the proofs from `zig_proofs.txt` after dalek's `verify_single` / `verify_multiple` ACCEPTED each (the tool panics on a rejection) | Rust; `bulletproofs` 4.0.0 and `merlin` 3.0.0 (dalek-cryptography, MIT), fetched by cargo, pinned in `Cargo.lock` |

From the module directory (`modules/bulletproofs`), through `hw run` as every build here:

```sh
# 1. only when this module's proofs should be re-checked by dalek:
zig run -OReleaseSafe -fllvm --cache-dir ../../.zig-cache \
    --dep bulletproofs -Mroot=tools/dalek/emit_zig_proofs.zig \
    --dep ct25519 -Mbulletproofs=src/root.zig -Mct25519=../ct25519/src/root.zig \
    > tools/dalek/zig_proofs.txt
# 2. regenerate the vectors (byte-identical for the same zig_proofs.txt):
cargo run -q --release --manifest-path tools/dalek/Cargo.toml \
    < tools/dalek/zig_proofs.txt > src/interop_vectors.zig
cargo clean --manifest-path tools/dalek/Cargo.toml
```

`-q` is load-bearing: without it cargo's progress lines can end up in the
redirected output.

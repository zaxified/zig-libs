# `tfhe` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test.

| file | produces | needs |
|---|---|---|
| `tfhers/` (Cargo project) | `src/testdata/tfhers_vectors.bin` (`vectors`): tfhe-rs 1.8.1's boolean parameter sets, 2 000 `SignedDecomposer` samples, a small `k = 2` set's keys / standard bootstrap and key-switch keys / ciphertexts / PBS, key-switch and gate outputs, and `DEFAULT_PARAMETERS` secret keys / ciphertexts / gate outputs. Deterministic seeds: regenerating is byte-identical. `check FILE` runs the other direction and panics on the first disagreement. | Rust; `tfhe` 1.8.1 (Zama, BSD-3-Clause-Clear, used as a black box, never shipped), fetched by cargo, pinned in `Cargo.lock` |
| `tfhers/emit_zig.zig` | this module's secret keys, bootstrap and key-switch keys, ciphertexts and gate outputs (small set and `tfhers_default`) for `check`; ~78 MB, fresh keys each run — write it under `.zig-cache`, never commit it | Zig |
| `tfhers/zig_checked.txt` | the transcript of the last `check` run | — |

From the module directory (`modules/tfhe`), through `hw run` as every build here:

```sh
# tfhe-rs -> this module (the committed vectors):
cargo run -q --release --manifest-path tools/tfhers/Cargo.toml -- vectors src/testdata/tfhers_vectors.bin
# this module -> tfhe-rs:
zig run -OReleaseSafe -fllvm --cache-dir ../../.zig-cache \
    --dep tfhe -Mroot=tools/tfhers/emit_zig.zig \
    --dep entropy -Mtfhe=src/root.zig -Mentropy=../entropy/src/root.zig \
    > ../../.zig-cache/tfhe-emit.bin
cargo run -q --release --manifest-path tools/tfhers/Cargo.toml -- check ../../.zig-cache/tfhe-emit.bin
cargo clean --manifest-path tools/tfhers/Cargo.toml
```

Only tfhe-rs's documentation and public signatures were read; its conventions
were recovered from what its public API returns (`../SPEC.md`, "Layout and
conventions").

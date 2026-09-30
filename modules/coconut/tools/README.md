# `coconut` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test.

| file | produces | needs |
|---|---|---|
| `vectors/` (Cargo project) | `src/interop_vectors.zig` — `cargo run -q --release --manifest-path modules/coconut/tools/vectors/Cargo.toml > modules/coconut/src/interop_vectors.zig` (through `hw run` in this repo) | Rust; `coconut-crypto` 0.14.0 (Apache-2.0, docknetwork/crypto) and arkworks 0.4 (MIT/Apache-2.0), fetched by cargo, pinned in `Cargo.lock` |

The tool deals threshold keys, issues partial PS credentials and aggregates them in the foreign
library with a fixed-seed RNG, then prints the values converted to this module's encodings
(ZCash compressed points, 32-byte big-endian scalars; details in the generated file header).
`interop_test.zig` consumes them. Regeneration is deterministic (byte-identical output).

Build output goes to `vectors/target/` — remove it with `cargo clean --manifest-path modules/coconut/tools/vectors/Cargo.toml` after a run.

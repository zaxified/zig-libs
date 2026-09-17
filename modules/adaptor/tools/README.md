# `adaptor` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test. Moved here on
2026-09-17 from a private `~/.cache` directory, where they were the only copy.

| file | produces | needs |
|---|---|---|
| `vectors/` (Cargo project) | `src/interop_vectors.zig` — `cargo run --release --manifest-path modules/adaptor/tools/vectors/Cargo.toml > modules/adaptor/src/interop_vectors.zig` | Rust; `schnorr_fun` 0.13 (0BSD), fetched by cargo, pinned in `Cargo.lock` |

Build output goes to `vectors/target/` — delete it after a run.

# rust_bench

Candidate side of `zig build bench-decimal` (`../bench.zig`): rust_decimal
1.42.1 (MIT, `=1.42.1`, default features off, `std` only) against the fixed
`Decimal`. `Cargo.lock` is committed; `bench.zig` runs `cargo build --release
--locked --offline` with `CARGO_TARGET_DIR=.zig-cache/bench-decimal/target`
(`cargo fetch` once for the registry).

Built crates (`cargo tree -e normal,build`): rust_decimal, arrayvec 0.7.8,
num-traits 0.2.19, autocfg 1.5.1. No proc-macros. Two build scripts, swept
2026-10-20: rust_decimal's `build.rs` rewrites its README.md into `OUT_DIR`
(doc codegen); num-traits' `build.rs` runs autocfg, which probes `rustc` and
emits `cfg`s. The other crates in the lock file (serde, syn, borsh, ...) belong
to optional features and are not built.

No BigDecimal counterpart exists in rust_decimal: only the fixed-size
workloads run here.

# rust_bench

Fastest-candidate side of `zig build bench-procrun` (`../bench.zig`): Rust
`std::process` (standard library only; no dependencies) on the same child
commands as the Zig side. `bench.zig` builds it with
`cargo build --release --locked --offline` and
`CARGO_TARGET_DIR=.zig-cache/bench-procrun/target`. `Cargo.lock` is committed.
The workloads are described in the header of `src/main.rs` and `../bench.zig`.
Not a test and not part of any lane.

# tsink_bench

The reference side of `zig build bench-tsdb` (`modules/tsdb/tools/bench.zig`):
a small Rust program over [tsink](https://github.com/h2337/tsink) (embedded
time-series database, MIT), crate **`tsink =0.10.2`** (pinned exactly in
`Cargo.toml`, `Cargo.lock` committed).

## What it measures

tsink with `WalSyncMode::PerAppend` ("Each append calls `fsync` before
acknowledging the write", tsink `docs/storage-engine.md`; it is also tsink's
default). This is the like-for-like durable mode for `tsdb`, whose every
`kvtree` commit is fsynced. One `insert_rows` call is one logical WAL write and
one `sync_data`. Workloads, data generators and the checksum mirror `bench.zig`
(its header describes them); keep the two in step.

## How to run

`zig build bench-tsdb` (from the repository root) builds this crate itself
(`cargo build --release --locked`, offline, `CARGO_TARGET_DIR=.zig-cache/bench-tsdb/target`)
and runs `tsink_bench <work dir> <workload>` once per workload and round. The
crates must be in the cargo cache (`cargo fetch` here once). Output:
`name \t ns/op \t count` on stdout, the banner on stderr. Data goes under
`<work dir>/tsink/` and is removed after each run.

## Source sweep (before the first build, 2026-10-20)

All 89 crates in `Cargo.lock` (cargo metadata, then `rg` over the fetched
sources):

- `tsink` itself: no `build.rs` (`build = false`), no proc macro, no
  `process::Command`, no network code; 8 `unsafe` occurrences in 3 files
  (`mmap.rs` 4, `fs_utils.rs` 2, `cgroup.rs` 2).
- Build scripts (27 crates): version/cfg probes via `$RUSTC --version`
  (crc32fast, proc-macro2, quote, serde, serde_core, thiserror, zmij,
  rustversion, libc, ...), `OUT_DIR` codegen (serde, serde_core, thiserror),
  and `zstd-sys`, which compiles its vendored zstd C sources with the `cc`
  crate (and copies headers into `OUT_DIR`). `wasm-bindgen-shared` runs `git`,
  but it is not in the Linux dependency tree (`cargo tree --target
  x86_64-unknown-linux-gnu`).
- Proc-macro crates in the tree: serde_derive, thiserror-impl,
  tracing-attributes, rustversion (plus windows-* and wasm-bindgen ones that a
  Linux build does not compile). No downloads, no network use, nothing writing
  outside `OUT_DIR`.
- Licences: all MIT / Apache-2.0 / BSD / Unlicense / Zlib compatible;
  `xxhash-rust` is BSL-1.0, `r-efi` (not built on Linux) lists LGPL as one of
  three alternatives.
